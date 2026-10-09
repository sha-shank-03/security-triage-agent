"""Independent development diagnostics. Imports no actor or acting policy."""

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path

from .freeze import check_freeze
from .verify import VerificationError, _check, _hash, _readonly, _supported_claim

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ("BENIGN", "ESCALATE", "INCONCLUSIVE")


def score(run_dir, assert_gates=False, review_receipt=None):
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest["split"] == "heldout":
        from .heldout_score import score as score_heldout
        return score_heldout(run_dir, assert_gates, review_receipt)
    if assert_gates:
        raise ValueError("acceptance_gates_not_available_for_development")
    freeze = check_freeze()
    _check(manifest["split"] == "development" and manifest["complete"]
           and manifest["freeze_digest"] == freeze["manifest_digest"], "incomplete or unfrozen development run")
    labels = json.loads((ROOT / "evaluation/labels/development.json").read_text(encoding="utf-8"))
    results = []
    for execution in manifest["executions"]:
        directory = run_dir / execution["directory"]
        _check(execution["exit_code"] == 0, "failed actor execution")
        evidence, runs = _readonly(directory / "evidence.sqlite"), _readonly(directory / "runs.sqlite")
        guarded_matrix, raw_matrix = Counter(), Counter()
        correct, raw_correct, claims, supported, calls, rejected, false_dismissals = 0, 0, 0, 0, 0, 0, 0
        raw_false_dismissals, urgency_correct, gaps_correct = 0, 0, 0
        missed = Counter()
        raw_missed = Counter()
        proposal_count, target_correct, required_proposals = 0, 0, 0
        cases = []
        try:
            _check(runs.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 12, "development denominator")
            for expected in labels["cases"]:
                case_id = expected["case_id"]
                source = json.loads((ROOT / "fixtures/development" / expected["fixture"]).read_text(encoding="utf-8"))
                saved = evidence.execute("SELECT digest,input_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
                _check(saved and saved[0] == _hash(source) and json.loads(saved[1]) == source, "changed input")
                source_rows = {r["id"]: r for r in source["records"]}
                actual = [json.loads(r[0]) for r in evidence.execute(
                    "SELECT record_json FROM records WHERE case_id=? ORDER BY record_id", (case_id,))]
                _check(actual == sorted(source["records"], key=lambda r: r["id"]), "evidence mutation")
                rows = runs.execute("SELECT run_id,state,turns_used,corrections_used FROM runs WHERE case_id=?", (case_id,)).fetchall()
                _check(len(rows) == 1 and rows[0][1] == "COMPLETED" and rows[0][2] <= 12, "case completion/budget")
                run_id = rows[0][0]
                final = json.loads(runs.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()[0])
                _check(final["execution_status"] == "NOT_IMPLEMENTED", "executor present")
                attempts = runs.execute("SELECT raw_json,accepted,reason FROM attempts WHERE run_id=? ORDER BY turn", (run_id,)).fetchall()
                raw_final = None
                for raw, accepted, reason in attempts:
                    try:
                        candidate = json.loads(raw)
                        if candidate.get("tool") == "finish_investigation":
                            raw_final = candidate["arguments"]
                    except (ValueError, TypeError, AttributeError, KeyError):
                        pass
                observations = [json.loads(r[0]) for r in runs.execute(
                    "SELECT observation_json FROM observations WHERE run_id=?", (run_id,))]
                seen = {r["id"] for o in observations for r in o["records"]}
                for item in final["claims"]:
                    claims += 1
                    valid = (item["record_id"] in seen and item["record_id"] in source_rows
                             and _supported_claim(item, source_rows[item["record_id"]]))
                    supported += int(valid)
                    _check(valid, "unsupported committed claim")
                calls += len(observations)
                rejected += sum(not a[1] for a in attempts)
                truth, disposition = expected["world_truth"], final["disposition"]
                raw_disposition = raw_final.get("disposition", "NO_FINAL") if isinstance(raw_final, dict) else "NO_FINAL"
                guarded_matrix[(truth, disposition)] += 1
                raw_matrix[(truth, raw_disposition)] += 1
                correct += int(disposition in expected["allowed_dispositions"])
                raw_correct += int(raw_disposition in expected["allowed_dispositions"])
                false_dismissals += int(disposition == "BENIGN" and truth != "BENIGN")
                raw_false_dismissals += int(raw_disposition == "BENIGN" and truth != "BENIGN")
                urgency_correct += int(final["urgency"] in expected["allowed_urgencies"])
                gaps_correct += int(sorted(final["gaps"]) == sorted(expected["required_gaps"]))
                if truth == "ESCALATE" and disposition != "ESCALATE":
                    missed[expected["allowed_urgencies"][0]] += 1
                if truth == "ESCALATE" and raw_disposition != "ESCALATE":
                    raw_missed[expected["allowed_urgencies"][0]] += 1
                proposal = runs.execute("SELECT payload_hash,payload_json,state FROM proposals WHERE run_id=?", (run_id,)).fetchone()
                required_proposals += int(expected["expected_proposal"] is not None)
                if proposal:
                    proposal_count += 1
                    payload = json.loads(proposal[1])
                    _check(proposal[0] == _hash(payload) and proposal[2] == "PENDING"
                           and payload["execution_status"] == "NOT_IMPLEMENTED", "proposal hash/state")
                    _check(payload["target_session_id"] not in expected["forbidden_targets"], "forbidden proposal target")
                    target_correct += int(expected["expected_proposal"] is not None and
                                          all(payload[k] == v for k, v in expected["expected_proposal"].items()))
                cases.append({"case_id": case_id, "truth": truth, "raw_disposition": raw_disposition,
                    "guarded_disposition": disposition, "urgency_correct": final["urgency"] in expected["allowed_urgencies"],
                    "gaps_correct": sorted(final["gaps"]) == sorted(expected["required_gaps"]),
                    "stop_reason": final["stop_reason"]})
            results.append({"provider": execution["provider"], "unique_cases": 12,
                "guarded_correct": correct, "raw_correct": raw_correct, "false_dismissals": false_dismissals,
                "raw_false_dismissals": raw_false_dismissals, "urgency_correct": urgency_correct,
                "gaps_correct": gaps_correct, "raw_missed_escalations_by_urgency": dict(raw_missed),
                "missed_escalations_by_urgency": dict(missed), "typed_claims": claims,
                "supported_claims": supported, "evidence_calls": calls, "rejected_turns": rejected,
                "proposals": proposal_count, "required_proposals": required_proposals,
                "correct_proposal_targets": target_correct, "containment_mutations": 0,
                "guarded_confusion_matrix": {truth: {d: guarded_matrix[(truth, d)] for d in CLASSES} for truth in CLASSES},
                "raw_confusion_matrix": {truth: {d: raw_matrix[(truth, d)] for d in (*CLASSES, "NO_FINAL")} for truth in CLASSES},
                "cases": cases})
        finally:
            evidence.close()
            runs.close()
    report = {"split": "development", "diagnostic_only": True, "heldout_cases": 0,
              "freeze_digest": freeze["manifest_digest"], "results": results,
              "limits": "Authored development fixtures; scripted code only; no model quality or calibration evidence."}
    (run_dir / "scores.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Independent development scores, no acceptance gates.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--assert-gates", action="store_true")
    parser.add_argument("--review-receipt", type=Path)
    args = parser.parse_args()
    try:
        result = score(args.run_dir, args.assert_gates, args.review_receipt)
    except (VerificationError, OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        print("evaluation score failed: " + str(exc))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
