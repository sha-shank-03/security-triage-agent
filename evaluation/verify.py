"""Demo outcome verifier: standard library, no acting-policy imports."""

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class VerificationError(ValueError):
    pass


def _check(condition, message):
    if not condition:
        raise VerificationError(message)


def _hash(value):
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _readonly(path):
    if not path.is_file():
        raise VerificationError("missing database: " + path.name)
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _supported_claim(item, record):
    # Intentionally independent of the host's claim builders/validators.
    if set(item) != {"kind", "record_id", "record_version", "value"}:
        return False
    if type(item["value"]) is not bool or type(item["record_version"]) is not int:
        return False
    if item["record_version"] != record["version"]:
        return False
    data, kind = record["data"], item["kind"]
    if kind == "AUTH_SUCCESS":
        return record["kind"] == "auth" and item["value"] == (data["outcome"] == "success")
    if kind == "MFA_DENIED":
        return record["kind"] == "auth" and item["value"] == (data["mfa"] == "denied")
    mappings = {"DEVICE_MANAGED": ("device", "managed"), "NETWORK_APPROVED": ("network", "approved"),
                "TRAVEL_APPROVED": ("travel", "approved"),
                "RESOURCE_SENSITIVE": ("resource", "sensitive"), "COVERAGE_COMPLETE": ("coverage", "complete")}
    if kind not in mappings:
        return False
    expected_kind, field = mappings[kind]
    return record["kind"] == expected_kind and item["value"] == data[field]


def verify(run_dir, suite="demo"):
    if suite != "demo":
        raise VerificationError("M1 supports only the three-case demo suite")
    labels = json.loads((ROOT / "evaluation" / "labels" / "demo.json").read_text(encoding="utf-8"))
    evidence = _readonly(run_dir / "evidence.sqlite")
    runs = _readonly(run_dir / "runs.sqlite")
    claims, reads, proposals = 0, 0, 0
    try:
        expected_ids = {case["case_id"] for case in labels["cases"]}
        _check({r[0] for r in evidence.execute("SELECT case_id FROM cases")} == expected_ids, "evidence case set")
        _check({r[0] for r in runs.execute("SELECT case_id FROM runs")} == expected_ids, "run case set")
        for expected in labels["cases"]:
            case_id = expected["case_id"]
            source = json.loads((ROOT / "fixtures" / "demo" / expected["fixture"]).read_text(encoding="utf-8"))
            saved = evidence.execute("SELECT digest,input_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
            _check(saved[0] == _hash(source) and json.loads(saved[1]) == source, "source snapshot changed")
            actual_records = [json.loads(r[0]) for r in evidence.execute(
                "SELECT record_json FROM records WHERE case_id=? ORDER BY record_id", (case_id,))]
            _check(actual_records == sorted(source["records"], key=lambda r: r["id"]), "containment/evidence mutation")
            run = runs.execute("SELECT run_id,snapshot_digest,provider,policy,prompt,state FROM runs WHERE case_id=?",
                               (case_id,)).fetchone()
            run_id = run[0]
            versions = {"scripted_policy_v1": "triage-m1-v1", "scripted_policy_v2": "triage-m2-v1"}
            _check(run[1] == _hash(source) and run[2] in versions, "run provenance")
            _check(run[3:5] == (versions[run[2]], versions[run[2]]) and run[5] == "COMPLETED", "run state/version")
            final = json.loads(runs.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()[0])
            _check(final["disposition"] == expected["disposition"], "wrong disposition: " + case_id)
            _check(final["urgency"] == expected["urgency"], "wrong urgency: " + case_id)
            _check(final["gaps"] == expected["gaps"], "gap omitted/changed: " + case_id)
            _check(final["execution_status"] == "NOT_IMPLEMENTED", "executor status")
            _check(final["stop_reason"] == "validated_finish", "unexpected fallback in demo")
            attempts = runs.execute("SELECT turn,raw_json,accepted,reason FROM attempts WHERE run_id=? ORDER BY turn",
                                    (run_id,)).fetchall()
            _check(1 <= len(attempts) <= 12, "unbounded provider loop")
            finished = [json.loads(a[1]) for a in attempts if a[2] == 1 and a[3] == "validated_finish"]
            _check(len(finished) == 1 and finished[0]["tool"] == "finish_investigation", "missing/duplicate accepted finish")
            _check(finished[0]["arguments"] == {k: v for k, v in final.items()
                                               if k not in ("execution_status", "stop_reason")},
                   "accepted provider output differs from committed result")
            observed = runs.execute("SELECT turn,observation_json FROM observations WHERE run_id=? ORDER BY turn",
                                    (run_id,)).fetchall()
            _check(len(observed) >= 3, "missing real local evidence calls")
            rows_by_id = {r["id"]: r for r in source["records"]}
            seen = set()
            for turn, raw_observation in observed:
                observation = json.loads(raw_observation)
                attempt = next((a for a in attempts if a[0] == turn), None)
                _check(attempt is not None and attempt[2] == 1 and attempt[3] == "evidence_read", "trace/attempt mismatch")
                call = json.loads(attempt[1])
                _check(call["tool"] == observation["tool"] and call["arguments"] == observation["arguments"], "tool trace mismatch")
                _check(observation["snapshot_digest"] == run[1] and not observation["truncated"], "observation scope/budget")
                for record in observation["records"]:
                    _check(record == rows_by_id.get(record["id"]), "invented tool record")
                    _check(_time(record["ingested_at"]) <= _time(source["cutoff"])
                           and _time(record["event_time"]) <= _time(source["cutoff"]), "future evidence")
                    seen.add(record["id"])
            for item in final["claims"]:
                _check(item["record_id"] in seen, "uncited observation")
                _check(_supported_claim(item, rows_by_id[item["record_id"]]), "unsupported typed claim")
                claims += 1
            _check(bool(final["claims"]), "empty demo claims")
            _check(final["proposal"] == expected["proposal"], "final proposal mismatch")
            saved_proposals = runs.execute("SELECT payload_hash,payload_json,state FROM proposals WHERE run_id=?",
                                          (run_id,)).fetchall()
            if expected["proposal"] is None:
                _check(not saved_proposals, "proposal on benign/inconclusive case")
            else:
                _check(len(saved_proposals) == 1, "duplicate/missing proposal")
                proposal_hash, raw_payload, state = saved_proposals[0]
                payload = json.loads(raw_payload)
                _check(state == "PENDING" and proposal_hash == _hash(payload), "proposal state/hash")
                target = rows_by_id[payload["target_record_id"]]
                _check(target["id"] in seen and target["kind"] == "auth" and target["data"]["outcome"] == "success"
                       and target["data"]["session_id"] == payload["target_session_id"], "proposal target linkage")
                _check({key: payload[key] for key in expected["proposal"]} == expected["proposal"], "wrong containment target")
                _check(payload["case_id"] == case_id and payload["snapshot_digest"] == run[1]
                       and payload["snapshot_version"] == source["snapshot_version"]
                       and payload["version"] == 1 and payload["policy"] == run[3]
                       and payload["execution_status"] == "NOT_IMPLEMENTED", "proposal binding")
                proposals += 1
            reads += len(observed)
        return {"suite": suite, "unique_cases": len(labels["cases"]), "dispositions_correct": 3,
                "typed_claims_supported": claims, "evidence_calls": reads,
                "pending_proposals": proposals, "containment_mutations": 0,
                "checked_invariants": ["dispositions", "urgencies", "gaps", "typed_claims", "tool_traces",
                                       "provider_final_binding", "pending_proposals", "source_immutability"],
                "evidence_kind": "scripted_workflow_integration"}
    finally:
        evidence.close()
        runs.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Independently check persisted M1 demo outcomes.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--suite", choices=["demo"], required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.run_dir, args.suite)
    except (VerificationError, OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        print("verification failed: " + str(exc))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
