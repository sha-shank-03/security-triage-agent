"""Independent raw/guarded domain scorer. No security_triage/actor imports."""

import argparse
import json
import math
import sqlite3
from collections import Counter
from pathlib import Path

from .independent import adverse_successes, visible_rows
from .upgrade_dataset import EVAL_MANIFEST, ROOT, VERSION, file_sha, load_inputs, load_labels, verify_dataset
from .upgrade_verify import load_committed, validate_packet, verify_directory
from .verify import VerificationError, _check, _hash, _supported_claim, _time

CLASSES = ("BENIGN", "ESCALATE", "INCONCLUSIVE", "NO_FINAL", "NO_RESULT", "INVALID")
PROVIDERS = ("complete-playbook-v2", "gateway-double")


def domain_truth(source):
    """Independent factual adjudication; never branches on case ID or family."""
    rows = [r for kind in ("identity", "auth", "resource", "device", "network", "travel", "coverage") for r in visible_rows(source, kind)]
    successes = [r for r in rows if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
    gaps = sorted(r["id"] for r in rows if r["kind"] == "coverage" and not r["data"]["complete"])
    if adverse_successes(rows):
        privileged = any(r["kind"] == "identity" and r["data"]["privileged"] for r in rows)
        return "ESCALATE", "CRITICAL" if privileged else "HIGH", gaps
    complete = all(any(r["kind"] == "coverage" and r["data"]["stream"] == stream and r["data"]["complete"]
                       and _time(r["data"]["from"]) <= _time(source["window_start"])
                       and _time(r["data"]["to"]) >= _time(source["cutoff"]) for r in rows) for stream in ("auth", "resource"))
    benign = bool(successes) and complete and not gaps and not any(
        r["kind"] == "auth" and r["data"]["mfa"] == "denied" or r["kind"] == "resource" and r["data"]["sensitive"] for r in rows)
    if successes:
        last = successes[-1]
        benign = benign and all(s["data"]["device_id"] == last["data"]["device_id"] and s["data"]["ip"] == last["data"]["ip"]
                               and s["data"]["mfa"] == "satisfied" for s in successes)
        benign = benign and any(r["kind"] == "device" and r["data"]["managed"] and r["data"]["device_id"] == last["data"]["device_id"] for r in rows)
        benign = benign and any(r["kind"] in ("network", "travel") and r["data"]["approved"] and r["data"]["ip"] == last["data"]["ip"]
                               and _time(r["data"]["valid_from"]) <= _time(source["window_start"])
                               and _time(r["data"]["valid_to"]) >= _time(source["cutoff"]) for r in rows)
    return "BENIGN" if benign else "INCONCLUSIVE", source["alert"]["priority"], gaps


def check_label(label, source):
    truth, urgency, gaps = domain_truth(source)
    _check(label["case_id"] == source["case_id"] and label["world_truth"] == truth
           and label["allowed_dispositions"] == [truth] and label["allowed_urgencies"] == [urgency]
           and sorted(label["required_gaps"]) == gaps and label["expected_proposal"] is None
           and label["severity_stratum"] == source["alert"]["priority"] and label["label_exposure"] == "worker-exposed",
           "label/domain/source disagreement")


def score_bundle(bundle, source, label):
    """Pure kernel used after separate committed-DB verification by score()."""
    check_label(label, source)
    validate_packet(bundle, source)
    raw, guarded = bundle["outcome"]["raw"], bundle["outcome"]["guarded"]
    seen = {r["id"]: r for a in bundle["attempts"] if a["observation"] for r in a["observation"]["records"]}
    raw_claims = raw.get("claims", []) if isinstance(raw, dict) and isinstance(raw.get("claims"), list) else []
    support = sum(isinstance(c, dict) and c.get("record_id") in seen and _supported_claim(c, seen[c["record_id"]]) for c in raw_claims)
    raw_class = raw.get("disposition", "NO_FINAL") if isinstance(raw, dict) else "NO_FINAL"
    if raw_class not in CLASSES: raw_class = "INVALID"
    raw_urgency = raw.get("urgency") if isinstance(raw, dict) else None
    truth = label["world_truth"]
    state = bundle["run"]["state"]
    return {"case_id": source["case_id"], "truth": truth, "family": label["family"], "severity_stratum": label["severity_stratum"],
            "required_urgency": label["allowed_urgencies"][0], "raw": raw_class, "guarded": guarded["disposition"],
            "raw_correct": raw_class in label["allowed_dispositions"], "guarded_correct": guarded["disposition"] in label["allowed_dispositions"],
            "raw_urgency_correct": raw_urgency in label["allowed_urgencies"], "guarded_urgency_correct": guarded["urgency"] in label["allowed_urgencies"],
            "gaps_correct": sorted(guarded["gaps"]) == sorted(label["required_gaps"]), "state": state,
            "stop_reason": bundle["outcome"]["reason"], "verified": True, "raw_claims": len(raw_claims), "raw_supported_claims": support,
            "guarded_claims": len(guarded["claims"]), "attempts": bundle["run"]["attempts"], "observations": len([a for a in bundle["attempts"] if a["observation"]]),
            "host_intervention": bundle["outcome"]["reason"] != "validated_finish",
            "task_success": state == "COMPLETED" and guarded["disposition"] in label["allowed_dispositions"]
                            and guarded["urgency"] in label["allowed_urgencies"] and sorted(guarded["gaps"]) == sorted(label["required_gaps"]),
            "elapsed_seconds": bundle["run"]["elapsed"], "actual_cost_minor_units": None, "mutations": 0}


def latency(values):
    values = sorted(v for v in values if type(v) in (int, float) and math.isfinite(v) and v >= 0)
    if not values: return {"N": 0, "p50": None, "p95": None, "max": None, "method": "nearest rank"}
    pick = lambda p: values[max(0, math.ceil(p * len(values)) - 1)]
    return {"N": len(values), "p50": pick(.50), "p95": pick(.95), "max": values[-1], "method": "nearest rank; includes recorded failures/handoffs"}


def aggregate(results, providers):
    report = {"unique_cases": len({r["case_id"] for r in results}), "executions": len(results), "providers": {}, "paired": None}
    for provider in providers:
        rows = [r for r in results if r["provider"] == provider]
        matrices = {}
        for mode in ("raw", "guarded"):
            counts = Counter((r["truth"], r[mode]) for r in rows)
            matrices[mode] = {truth: {out: counts[truth, out] for out in CLASSES} for truth in CLASSES[:3]}
        misses = lambda mode, key: dict(Counter(r[key] for r in rows if r["truth"] == "ESCALATE" and r[mode] != "ESCALATE"))
        report["providers"][provider] = {"N": len(rows), "raw_correct": sum(r["raw_correct"] for r in rows),
            "guarded_correct": sum(r["guarded_correct"] for r in rows), "task_success": sum(r["task_success"] for r in rows),
            "states": dict(Counter(r["state"] for r in rows)), "verified": sum(r["verified"] for r in rows), "confusion": matrices,
            "per_class_N": dict(Counter(r["truth"] for r in rows)),
            "raw_false_benign": sum(r["raw"] == "BENIGN" and r["truth"] != "BENIGN" for r in rows),
            "guarded_false_benign": sum(r["guarded"] == "BENIGN" and r["truth"] != "BENIGN" for r in rows),
            "misses_by_alert_severity": {m: misses(m, "severity_stratum") for m in ("raw", "guarded")},
            "misses_by_required_urgency": {m: misses(m, "required_urgency") for m in ("raw", "guarded")},
            "raw_claims": sum(r["raw_claims"] for r in rows), "raw_supported_claims": sum(r["raw_supported_claims"] for r in rows),
            "guarded_claims_supported": sum(r["guarded_claims"] for r in rows), "host_interventions": sum(r["host_intervention"] for r in rows),
            "execution_wall_latency_seconds": latency([r["execution_wall_seconds"] for r in rows]),
            "host_elapsed_latency_seconds": latency([r["elapsed_seconds"] for r in rows]),
            "actual_cost_coverage": {"known": 0, "N": len(rows)}, "actual_total_cost_minor_units": None,
            "actual_cost_per_success_minor_units": None, "currency": "INR", "approval_wait_seconds": 0,
            "cost_limit": "No billing/total operating cost measured. Local doubles/scripted baseline are not live inference.",
            "cases": rows}
    if len(providers) == 2:
        first, second = providers
        index = {(r["case_id"], r["provider"]): r for r in results}
        comparisons = []
        for case_id in sorted({r["case_id"] for r in results}):
            a, b = index[case_id, first], index[case_id, second]
            comparisons.append({"case_id": case_id, "winner": first if a["guarded_correct"] > b["guarded_correct"] else second if b["guarded_correct"] > a["guarded_correct"] else "tie",
                                "states": {first: a["state"], second: b["state"]}})
        report["paired"] = {"providers": providers, "counts": dict(Counter(c["winner"] for c in comparisons)), "cases": comparisons}
    report["limits"] = "Worker-exposed correlated fictional tasks; diagnostic contracts only. No uplift gate, unseen/model/SOC accuracy or significance claim."
    return report


def score(out):
    verify_dataset()
    manifest = json.loads((out / "manifest.json").read_text())
    split, providers = manifest["split"], manifest["providers"]
    inputs, sources = load_inputs(split); labels = load_labels(split)
    truth = {c["case_id"]: c for c in labels["cases"]}
    _check(manifest["version"] == VERSION and manifest["suite"] == "split" and manifest["exposure"] == "worker-exposed" and manifest["labels_loaded"] is False
           and 1 <= len(providers) <= 2 and len(set(providers)) == len(providers) and not set(providers) - set(PROVIDERS), "run attribution/providers")
    _check(manifest["input_manifest_sha256"] == file_sha(ROOT / f"evaluation/upgrade_sets/{split}-v1.inputs.json")
           and manifest["eval_manifest_sha256"] == file_sha(ROOT / EVAL_MANIFEST), "run/input/eval pins")
    frozen = json.loads((ROOT / EVAL_MANIFEST).read_text())
    _check(manifest["configuration"] == frozen["configuration"], "unequal or altered common authority/budget")
    expected = {(s["case_id"], p) for _, s in sources for p in providers}
    entries = {(e["case_id"], e["provider"]): e for e in manifest["executions"]}
    _check(set(entries) == expected and len(manifest["executions"]) == len(expected), "missing/duplicate execution denominator")
    results = []
    for item, source in sources:
        label = truth[source["case_id"]]; check_label(label, source)
        for provider in providers:
            entry = entries[source["case_id"], provider]
            _check(entry["directory"] == source["case_id"] + "--" + provider and entry["fixture_sha256"] == item["sha256"]
                   and entry["mode"] == ("SCRIPTED_BASELINE" if provider == "complete-playbook-v2" else "LOCAL_DOUBLE")
                   and entry["actual_cost_minor_units"] is None and entry["paid_model_calls"] == 0, "entry binding/cost/mode")
            row = {"case_id": source["case_id"], "truth": label["world_truth"], "family": label["family"],
                   "severity_stratum": label["severity_stratum"], "required_urgency": label["allowed_urgencies"][0],
                   "raw": "NO_RESULT", "guarded": "NO_RESULT", "raw_correct": False, "guarded_correct": False,
                   "task_success": False, "verified": False, "state": entry["status"], "stop_reason": entry.get("reason", "unexecuted"),
                   "raw_claims": 0, "raw_supported_claims": 0, "guarded_claims": 0, "host_intervention": False,
                   "elapsed_seconds": None, "actual_cost_minor_units": None}
            _check(entry["status"] in ("PENDING", "STARTED", "FAILED", "COMPLETED", "HANDOFF", "CANCELLED"), "execution state")
            if entry["status"] == "STARTED" or entry["status"] == "PENDING" and (out / entry["directory"]).exists():
                row.update(state="INTERRUPTED_UNKNOWN", stop_reason="no_verified_terminal_receipt")
            if entry["status"] not in ("PENDING", "STARTED", "FAILED"):
                directory = out / entry["directory"]
                try:
                    for name, key in (("packet.json", "packet_sha256"), ("state.sqlite", "state_sha256"), ("evidence.sqlite", "evidence_sha256")):
                        _check(file_sha(directory / name) == entry[key], "run artifact replaced")
                    verify_directory(directory, source)
                    bundle = load_committed(directory / "state.sqlite")
                    _check(bundle["run"]["config"] == manifest["configuration"] and bundle["run"]["versions"]["code_sha256"] == manifest["code_sha256"]
                           and bundle["run"]["state"] == entry["status"] and bundle["outcome"]["reason"] == entry["reason"], "run/entry/budget binding")
                    if provider == "complete-playbook-v2":
                        events = [e for e in bundle["events"] if e["kind"] == "baseline_contract"]
                        _check(len(events) == 1 and events[0]["data"]["policy_sha256"] == file_sha(ROOT / "security_triage/complete_playbook.py")
                               and events[0]["data"]["provider"] == provider and events[0]["data"]["genuine_model"] is False, "baseline attribution")
                    else:
                        events = [e for e in bundle["events"] if e["kind"] == "local_double_contract"]
                        _check(len(events) == 1 and events[0]["data"]["authorization_present"] is False and events[0]["data"]["genuine_model"] is False,
                               "double attribution")
                    row.update(score_bundle(bundle, source, label))
                except (VerificationError, OSError, ValueError, KeyError, TypeError, sqlite3.Error):
                    row.update(state="CORRUPT", stop_reason="independent_domain_or_trace_verification_failed")
            wall = entry["execution_wall_seconds"]
            _check(wall is None and entry["status"] in ("PENDING", "STARTED") or type(wall) in (int, float) and math.isfinite(wall) and 0 <= wall <= 300,
                   "latency missing/fabricated")
            _check(row["elapsed_seconds"] is None or wall + .01 >= row["elapsed_seconds"], "host duration exceeds recorded execution")
            row.update(provider=provider, execution_wall_seconds=wall)
            results.append(row)
    report = {"version": VERSION, "split": split, "exposure": "worker-exposed", "input_manifest_sha256": manifest["input_manifest_sha256"],
              "run_manifest_sha256": file_sha(out / "manifest.json"), **aggregate(results, providers)}
    (out / "scores.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Independent worker-exposed diagnostics; no model/score acceptance gate")
    parser.add_argument("--run-dir", type=Path, required=True); args = parser.parse_args()
    try: report = score(args.run_dir)
    except (VerificationError, OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        print(json.dumps({"passed": False, "reason": "upgrade_score_integrity_failed"})); return 1
    print(json.dumps(report, indent=2))
    return 2 if any(r["state"] == "CORRUPT" for p in report["providers"].values() for r in p["cases"]) else 0


if __name__ == "__main__": raise SystemExit(main())
