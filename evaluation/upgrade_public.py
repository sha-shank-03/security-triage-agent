"""Redacted first-report packaging, without actors, SQL, transports or rescoring."""

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from .upgrade_dataset import EVAL_MANIFEST, ROOT, VERSION, file_sha, load_inputs, load_labels, verify_dataset
from .upgrade_score import aggregate, latency
from .upgrade_verify import parse
from .verify import VerificationError, _check, _hash

PUBLIC_VERSION = "u2c-public-first-reports-v1"
PINS = "docs/evidence/U2B_FIRST_REPORT_PINS.json"
SUMMARY = "docs/evidence/U2B_FIRST_SUMMARY.json"
STATES = {"PENDING", "STARTED", "FAILED", "COMPLETED", "HANDOFF", "CANCELLED", "INTERRUPTED_UNKNOWN", "CORRUPT"}
TERMINAL = {"COMPLETED", "HANDOFF", "CANCELLED"}
LIMIT = ("Author-exposed correlated fictional tasks; scripted baseline and limited local HTTP double. "
         "Descriptive quality only; no model/SOC accuracy, uplift, unseen, sandbox, billing or deployment proof. "
         "Hashes bind previously verified reports; this package does not reverify private SQLite or replay traces.")


def read_json(path, expected=None):
    data = path.read_bytes()
    _check(len(data) <= 2 * 1024 * 1024, "public input size limit")
    _check(expected is None or hashlib.sha256(data).hexdigest() == expected, "first artifact hash mismatch")
    return parse(data.decode("utf-8"))


def fingerprints(pins, root=ROOT):
    _check(pins["version"] == PUBLIC_VERSION and pins["dataset_version"] == VERSION, "package version")
    _check(file_sha(root / "docs/UPGRADE_U2B_MANIFEST.json") == pins["source_manifest_sha256"]
           and file_sha(root / EVAL_MANIFEST) == pins["eval_manifest_sha256"], "historical source/evaluation fingerprint")
    source = read_json(root / "docs/UPGRADE_U2B_MANIFEST.json")
    # Packaging may append README; frozen executable/evaluation bytes remain exact.
    for name, expected in source["files"].items():
        if name.startswith(("security_triage/", "evaluation/", "fixtures/", "tests/")):
            _check(file_sha(root / name) == expected, "historical executable/input fingerprint")
    actor = {p.relative_to(root).as_posix(): file_sha(p) for p in sorted((root / "security_triage").glob("*.py"))}
    _check(_hash(actor) == pins["actor_code_sha256"] == source["actor_code_sha256"], "historical actor fingerprint")
    verify_dataset(root)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def summarize(rows, providers):
    """Every assigned slot counts; incomplete states never become task successes."""
    out = {}
    for provider in providers:
        rr = [r for r in rows if r["provider"] == provider]
        _check(all(r["state"] in STATES for r in rr), "unknown workflow state")
        for r in rr:
            _check(all(type(r[k]) is bool for k in ("verified", "raw_correct", "guarded_correct", "raw_urgency_correct",
                   "guarded_urgency_correct", "raw_gaps_correct", "guarded_gaps_correct", "raw_full_outcome_correct",
                   "guarded_full_outcome_correct", "task_success", "host_intervention")), "metric boolean type")
            _check(all(type(r[k]) is int and r[k] >= 0 for k in ("attempts", "observations")), "metric count type")
            for mode in ("raw", "guarded"):
                _check(r[mode + "_full_outcome_correct"] is (r[mode + "_correct"] and r[mode + "_urgency_correct"]
                       and r[mode + "_gaps_correct"]), "full outcome metric disagreement")
            _check(all(r[k] is None or finite(r[k]) for k in ("execution_wall_seconds", "host_elapsed_seconds")), "latency type")
            _check(r["actual_cost_minor_units"] is None, "unmeasured cost must remain null")
            _check(r["task_success"] is (r["verified"] and r["state"] == "COMPLETED" and r["guarded_full_outcome_correct"]), "fake task completion")
        counts = lambda key: sum(r[key] for r in rr)
        out[provider] = {
            "intended": len(rr), "dispatched": sum(r["dispatch_status"] != "PENDING" for r in rr),
            "terminal": sum(r["state"] in TERMINAL for r in rr), "completed": sum(r["state"] == "COMPLETED" for r in rr),
            "states": dict(Counter(r["state"] for r in rr)), "verified": counts("verified"),
            "raw_disposition_correct": counts("raw_correct"), "guarded_disposition_correct": counts("guarded_correct"),
            "raw_urgency_correct": counts("raw_urgency_correct"), "guarded_urgency_correct": counts("guarded_urgency_correct"),
            "raw_gaps_correct": counts("raw_gaps_correct"), "guarded_gaps_correct": counts("guarded_gaps_correct"),
            "raw_full_outcome_correct": counts("raw_full_outcome_correct"),
            "guarded_full_outcome_correct": counts("guarded_full_outcome_correct"), "task_success": counts("task_success"),
            "domain_failures": [r["case_id"] for r in rr if not r["task_success"]],
            "missed_escalations_by_alert_severity": {
                m: dict(Counter(r["severity_stratum"] for r in rr if r["truth"] == "ESCALATE" and r[m] != "ESCALATE"))
                for m in ("raw", "guarded")},
            "host_interventions": counts("host_intervention"),
            "attempts": counts("attempts"), "observations": counts("observations"),
            "execution_wall_latency_seconds": {**latency([r["execution_wall_seconds"] for r in rr]), "assigned_N": len(rr)},
            "host_elapsed_latency_seconds": {**latency([r["host_elapsed_seconds"] for r in rr]), "assigned_N": len(rr)},
            "actual_cost_coverage": {"known": 0, "N": len(rr)}, "actual_total_cost_minor_units": None,
            "actual_cost_per_success_minor_units": None, "currency": "INR",
            "approval_wait_seconds": 0, "approval_operations": 0,
        }
    paired = None
    if len(providers) == 2:
        index = {(r["case_id"], r["provider"]): r for r in rows}
        ids = sorted({r["case_id"] for r in rows})
        _check(len(index) == len(rows) == len(ids) * 2, "pair denominator")
        def pairs(key):
            a, b = providers
            counts = Counter(a if index[c, a][key] > index[c, b][key] else b if index[c, b][key] > index[c, a][key] else "tie" for c in ids)
            return {"N": len(ids), "counts": {p: counts[p] for p in [a, b, "tie"]}}
        paired = {"providers": providers, "guarded_disposition": pairs("guarded_correct"), "full_task": pairs("task_success")}
    return {"providers": out, "paired": paired}


def project_reports(split, manifest, scores, packets, root=ROOT):
    """Project pinned scores and final packets; never execute a policy or rescore."""
    inputs, sources = load_inputs(split, root)
    labels = {v["case_id"]: v for v in load_labels(split, root)["cases"]}
    providers = manifest["providers"]
    expected_providers = ["complete-playbook-v2"] if split == "development" else ["complete-playbook-v2", "gateway-double"]
    _check(providers == expected_providers and manifest["version"] == scores["version"] == VERSION
           and manifest["split"] == scores["split"] == split and manifest["suite"] == "split"
           and manifest["exposure"] == scores["exposure"] == "worker-exposed" and manifest["labels_loaded"] is False
           and manifest["unseen_tasks"] == 0, "report attribution")
    _check(manifest["input_manifest_sha256"] == scores["input_manifest_sha256"] == file_sha(root / f"evaluation/upgrade_sets/{split}-v1.inputs.json"), "input fingerprint")
    frozen = read_json(root / EVAL_MANIFEST)
    _check(manifest["configuration"] == frozen["configuration"], "common authority/budget")
    entries = {(e["case_id"], e["provider"]): e for e in manifest["executions"]}
    expected = {(s["case_id"], p) for _, s in sources for p in providers}
    old_rows = [r for p in providers for r in scores["providers"][p]["cases"]]
    index = {(r["case_id"], r["provider"]): r for r in old_rows}
    _check(set(entries) == set(index) == expected and len(entries) == len(manifest["executions"]) == len(old_rows), "missing/duplicate slots")
    reproduced = aggregate(old_rows, providers)
    _check(all(scores[k] == reproduced[k] for k in reproduced), "historical score aggregates/pairing changed")
    rows = []
    for item, source in sources:
        case = source["case_id"]; label = labels[case]
        for provider in providers:
            e, old = entries[case, provider], index[case, provider]
            _check(e["fixture_sha256"] == item["sha256"] and e["directory"] == case + "--" + provider
                   and e["mode"] == ("SCRIPTED_BASELINE" if provider == providers[0] else "LOCAL_DOUBLE")
                   and e["actual_cost_minor_units"] is None and e["paid_model_calls"] == 0 and e["cost_currency"] == "INR", "slot binding/cost")
            packet = packets[case, provider]
            run, outcome = packet["run"], packet["outcome"]
            _check(run["source"] == source and run["config"] == manifest["configuration"]
                   and run["versions"]["code_sha256"] == manifest["code_sha256"]
                   and run["state"] == old["state"] == e["status"] and e["status"] in TERMINAL
                   and outcome["reason"] == old["stop_reason"] == e["reason"], "packet/report completion binding")
            raw, guard = outcome["raw"], outcome["guarded"]
            _check(old["actual_cost_minor_units"] is None and old["verified"] is True
                   and raw["proposal"] is guard["proposal"] is None, "verification/cost/authority")
            expected_flags = {"raw_correct": raw["disposition"] in label["allowed_dispositions"],
                "guarded_correct": guard["disposition"] in label["allowed_dispositions"],
                "raw_urgency_correct": raw["urgency"] in label["allowed_urgencies"],
                "guarded_urgency_correct": guard["urgency"] in label["allowed_urgencies"],
                "gaps_correct": sorted(guard["gaps"]) == sorted(label["required_gaps"])}
            _check(all(type(old[k]) is bool and old[k] == v for k, v in expected_flags.items())
                   and old["raw"] == raw["disposition"] and old["guarded"] == guard["disposition"]
                   and old["truth"] == label["world_truth"] and old["required_urgency"] == label["allowed_urgencies"][0], "outcome metrics changed")
            _check(old["elapsed_seconds"] == run["elapsed"] and old["execution_wall_seconds"] == e["execution_wall_seconds"]
                   and finite(e["execution_wall_seconds"]) and e["execution_wall_seconds"] + .01 >= run["elapsed"], "latency binding")
            _check(old["attempts"] == run["attempts"] == len(packet["attempts"])
                   and old["observations"] == sum(bool(a["observation"]) for a in packet["attempts"]), "attempt/observation count binding")
            row = {k: old[k] for k in ("case_id", "provider", "truth", "severity_stratum", "required_urgency", "raw", "guarded",
                   "state", "verified", "raw_correct", "guarded_correct", "raw_urgency_correct", "guarded_urgency_correct",
                   "task_success", "host_intervention", "attempts", "observations", "execution_wall_seconds", "actual_cost_minor_units")}
            row.update(dispatch_status=e["status"], raw_urgency=raw["urgency"], guarded_urgency=guard["urgency"],
                       raw_gaps_correct=sorted(raw["gaps"]) == sorted(label["required_gaps"]), guarded_gaps_correct=old["gaps_correct"],
                       host_elapsed_seconds=run["elapsed"])
            for mode in ("raw", "guarded"):
                row[mode + "_full_outcome_correct"] = row[mode + "_correct"] and row[mode + "_urgency_correct"] and row[mode + "_gaps_correct"]
            rows.append(row)
    _check(manifest["complete"] is all(e["status"] in TERMINAL for e in entries.values()), "false batch completion")
    summarize(rows, providers)
    return rows


def build_summary(splits, pins):
    return {"version": PUBLIC_VERSION, "dataset_version": VERSION, "exposure": "worker-exposed",
            "unique_tasks": 24, "split_executions": 36, "demo_excluded": True,
            "provenance": {"pins_sha256": _hash(pins), "source_manifest_sha256": pins["source_manifest_sha256"],
                "eval_manifest_sha256": pins["eval_manifest_sha256"], "actor_code_sha256": pins["actor_code_sha256"],
                "raw_reports": {s: {k: p[k] for k in ("run_manifest_sha256", "scores_sha256", "input_manifest_sha256")}
                                for s, p in pins["splits"].items()}},
            "splits": {s: {"unique_tasks": len({r["case_id"] for r in rows}), "executions": len(rows),
                             **summarize(rows, pins["splits"][s]["providers"]), "cases": rows} for s, rows in splits.items()},
            "limits": LIMIT}


def validate_summary(summary, pins, root=ROOT):
    fingerprints(pins, root)
    _check(set(summary["splits"]) == set(pins["splits"]) == {"development", "capability"}, "public split denominator")
    splits = {}
    for split, anchor in pins["splits"].items():
        rows = summary["splits"][split]["cases"]
        _check(_hash(rows) == anchor["redacted_cases_sha256"], "first redacted outcomes changed")
        splits[split] = rows
    _check(summary == build_summary(splits, pins), "public summary changed or unapproved fields")
    return {"passed": True, "unique_tasks": 24, "split_executions": 36,
            "quality_gate": False, "private_state_reverified": False}


def export_summary(directories, out, root=ROOT):
    pins = read_json(root / PINS); fingerprints(pins, root)
    splits = {}
    for split, directory in directories.items():
        anchor = pins["splits"][split]
        manifest = read_json(directory / "manifest.json", anchor["run_manifest_sha256"])
        scores = read_json(directory / "scores.json", anchor["scores_sha256"])
        _check(manifest["eval_manifest_sha256"] == pins["eval_manifest_sha256"]
               and manifest["code_sha256"] == pins["actor_code_sha256"]
               and scores["run_manifest_sha256"] == anchor["run_manifest_sha256"], "first run fingerprints")
        packets = {}
        for e in manifest["executions"]:
            name = e["case_id"] + "--" + e["provider"]
            _check(e["directory"] == name and "/" not in name and "\\" not in name and ".." not in name, "packet path")
            _check(e["packet_sha256"] == anchor["packet_sha256"][name], "first packet binding")
            packets[e["case_id"], e["provider"]] = read_json(directory / name / "packet.json", e["packet_sha256"])
        splits[split] = project_reports(split, manifest, scores, packets, root)
    summary = build_summary(splits, pins); validate_summary(summary, pins, root)
    # Fresh destination, fully checked before any publication-file write.
    with out.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description="First-report redacted export/validation; no evaluation or inference")
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--development-dir", type=Path); parser.add_argument("--capability-dir", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.validate and not any((args.development_dir, args.capability_dir, args.out)):
            result = validate_summary(read_json(args.validate), read_json(ROOT / PINS))
        elif not args.validate and all((args.development_dir, args.capability_dir, args.out)):
            summary = export_summary({"development": args.development_dir, "capability": args.capability_dir}, args.out)
            result = {"exported": True, "unique_tasks": summary["unique_tasks"], "split_executions": summary["split_executions"]}
        else:
            raise VerificationError("select validation or complete first-report export")
    except (VerificationError, OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"passed": False, "reason": "public_report_integrity_failed"})); return 1
    print(json.dumps(result)); return 0


if __name__ == "__main__": raise SystemExit(main())
