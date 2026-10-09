"""Independent persisted heldout outcomes, repeated semantic traces and gates."""

import json
from pathlib import Path

from .heldout_freeze import check_freeze, require_review
from .independent import validate_case
from .metrics import gates, summarize
from .verify import _check, _hash, _readonly

ROOT = Path(__file__).resolve().parents[1]


def load_case(evidence, runs, source, provider, iteration):
    saved = evidence.execute("SELECT digest,input_json FROM cases WHERE case_id=?", (source["case_id"],)).fetchone()
    _check(saved is not None, "missing source case")
    cursor = runs.execute("SELECT * FROM runs WHERE case_id=?", (source["case_id"],))
    names = [column[0] for column in cursor.description]
    records = cursor.fetchall()
    _check(len(records) == 1, "duplicate or missing run")
    row = dict(zip(names, records[0]))
    row["config"] = json.loads(row.pop("config_json"))
    expected_provider = "scripted_policy_v2" if provider == "scripted" else "fixed_six_reads_v1"
    _check(row["provider"] == expected_provider and row["request_id"] == "heldout-repeat-" + str(iteration),
           "provider/repeat identity")
    run_id = row["run_id"]
    disposition = runs.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()
    _check(disposition is not None, "missing committed disposition")
    registry = runs.execute("SELECT version,digest,context_json FROM current_snapshots WHERE case_id=?",
                            (source["case_id"],)).fetchone()
    _check(registry is not None, "missing snapshot registry")
    completion = runs.execute("SELECT data_json FROM audit_events WHERE event='run_completed' AND object_id=?",
                              (run_id,)).fetchall()
    _check(len(completion) == 1, "completion audit cardinality")
    return {"source": source, "evidence_input": json.loads(saved[1]), "snapshot_digest": saved[0],
        "stored_records": [(case, rid, kind, json.loads(raw)) for case, rid, kind, raw in evidence.execute(
            "SELECT case_id,record_id,kind,record_json FROM records WHERE case_id=? ORDER BY record_id", (source["case_id"],))],
        "run": row, "final": json.loads(disposition[0]),
        "attempts": [{"turn": turn, "raw": raw, "accepted": accepted, "reason": reason, "usage": json.loads(usage)}
            for turn, raw, accepted, reason, usage in runs.execute(
                "SELECT turn,raw_json,accepted,reason,usage_json FROM attempts WHERE run_id=? ORDER BY turn", (run_id,))],
        "observations": [{"turn": turn, "observation": json.loads(raw)} for turn, raw in runs.execute(
            "SELECT turn,observation_json FROM observations WHERE run_id=? ORDER BY turn", (run_id,))],
        "proposals": [{"id": pid, "hash": hashed, "payload": json.loads(raw), "state": state, "version": version}
            for pid, hashed, raw, state, version in runs.execute(
                "SELECT proposal_id,payload_hash,payload_json,state,version FROM proposals WHERE run_id=?", (run_id,))],
        "reviews": list(runs.execute("SELECT request_id FROM reviews WHERE proposal_id IN "
                                    "(SELECT proposal_id FROM proposals WHERE run_id=?)", (run_id,))),
        "current_snapshot": {"version": registry[0], "digest": registry[1], "context": json.loads(registry[2])},
        "completion_audit": json.loads(completion[0][0])}


def score(run_dir, assert_gates=False, review_receipt=None):
    freeze = check_freeze()
    review = require_review(freeze, review_receipt)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    _check(manifest["split"] == "heldout" and manifest["complete"] and not manifest["unexecuted"]
           and manifest["freeze_digest"] == freeze["manifest_digest"] and manifest["review_digest"] == _hash(review),
           "unreviewed/changed/incomplete heldout manifest")
    labels = json.loads((ROOT / "evaluation/labels/heldout-v1.json").read_text(encoding="utf-8"))["cases"]
    expected_executions = {(provider, iteration) for provider in ("scripted", "baseline") for iteration in range(1, 4)}
    actual = [(e["provider"], e["repeat"]) for e in manifest["executions"]]
    _check(len(actual) == 6 and set(actual) == expected_executions, "missing/duplicate repeat denominator")
    per_repeat, digests, timings = {}, {}, {}
    for execution in manifest["executions"]:
        provider, iteration = execution["provider"], execution["repeat"]
        _check(execution["directory"] == provider + "-repeat-" + str(iteration) and execution["exit_code"] == 0,
               "invalid execution directory or failed actor")
        directory = run_dir / execution["directory"]
        evidence, runs = _readonly(directory / "evidence.sqlite"), _readonly(directory / "runs.sqlite")
        outcomes = []
        try:
            _check(evidence.execute("PRAGMA user_version").fetchone()[0] == 1
                   and runs.execute("PRAGMA user_version").fetchone()[0] == 2, "schema version")
            ids = {c["case_id"] for c in labels}
            _check({r[0] for r in evidence.execute("SELECT case_id FROM cases")} ==
                   {r[0] for r in runs.execute("SELECT case_id FROM runs")} == ids, "case population")
            for label in labels:
                source = json.loads((ROOT / "fixtures/heldout" / label["fixture"]).read_text(encoding="utf-8"))
                outcomes.append(validate_case(load_case(evidence, runs, source, provider, iteration)))
        finally:
            evidence.close()
            runs.close()
        per_repeat.setdefault(provider, []).append({"repeat": iteration, "metrics": summarize(outcomes, labels)})
        digests.setdefault(provider, {})[iteration] = {o["case_id"]: o["semantic_digest"] for o in outcomes}
        timings.setdefault(provider, []).append(execution["wall_seconds"])
    deterministic = all(digests[p][1] == digests[p][2] == digests[p][3] for p in digests)
    reports = {provider: next(r["metrics"] for r in repeats if r["repeat"] == 1)
               for provider, repeats in per_repeat.items()}
    rubric = json.loads((ROOT / "evaluation/heldout_rubric_v1.json").read_text(encoding="utf-8"))
    gate_result = gates(reports, rubric, True, deterministic)
    report = {"schema_version": 2, "split": "heldout", "dataset_version": "heldout-v1",
              "unique_cases": 36, "case_executions": 216, "providers": reports, "repeats": per_repeat,
              "semantic_outcomes_and_traces_equal": deterministic, "semantic_digests": digests,
              "actor_batch_wall_seconds": timings, "freeze_digest": freeze["manifest_digest"],
              "review_digest": _hash(review), "gates": gate_result,
              "model_usage": {"inference_calls": 0, "tokens": None},
              "limits": "Same-author synthetic/scripted regression; no independent population, live-model performance or calibration."}
    (run_dir / "scores.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# Heldout-v1 scripted regression", "", "Unique cases: 36; executions: 216; repeats do not enlarge the sample.",
             "", "Dataset and rubric reviewed before execution. Same author, synthetic inputs, no model inference.", "",
             "| Metric (first repeat; repeats checked separately) | Adaptive | Baseline |", "| --- | ---: | ---: |"]
    for metric in ("correct_dispositions", "malicious_benign_dismissals", "correct_benign", "correct_inconclusive",
                   "supported_claims_and_references", "proposal_target_action_errors", "gap_matches"):
        cells = [str(reports[p]["guarded"][metric]["numerator"]) + "/" +
                 str(reports[p]["guarded"][metric]["denominator"]) for p in ("scripted", "baseline")]
        lines.append("| " + metric + " | " + " | ".join(cells) + " |")
    lines += ["", "Raw/guarded confusion matrices, severity and urgency errors, cases, targets, gaps, trace digests, "
              "rejections and batch timing are in scores.json.", "",
              "Gate status: " + ("passed" if gate_result["passed"] else "FAILED") + ". No baseline uplift gate.", "",
              "No hosted CI, real SOC accuracy, model quality or human productivity claim follows from these results."]
    (run_dir / "scores.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if assert_gates and not gate_result["passed"]:
        raise ValueError("heldout_gates_failed_scores_preserved")
    return report
