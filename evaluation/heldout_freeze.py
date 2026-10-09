"""Versioned heldout static freeze plus independent-review prerequisite."""

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .freeze import check_freeze as check_development
from .verify import _hash, _supported_claim

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ["evaluation/label_schema_v2.json", "evaluation/labels/heldout-v1.json",
          "evaluation/heldout_rubric_v1.json", "docs/HELDOUT_REVIEW.md", "docs/BASELINE.md",
          "evaluation/development_freeze.json"] + [
          "security_triage/" + name for name in ("baseline.py", "providers.py", "contracts.py", "policy.py",
          "tools.py", "store.py", "workflow.py", "review.py", "loop.py", "ollama.py", "cli.py", "reports.py")] + [
          "evaluation/" + name for name in ("independent.py", "metrics.py", "heldout_run.py", "heldout_score.py",
          "heldout_freeze.py", "run.py", "score.py", "verify.py")]


def validate_labels(labels, schema, snapshots, rubric):
    props = schema["properties"]["cases"]["items"]["properties"]
    cases = labels["cases"]
    if (set(labels) != {"schema_version", "dataset_version", "split", "purpose", "cases"}
            or labels["schema_version"] != 2 or labels["dataset_version"] != "heldout-v1"
            or labels["split"] != "heldout" or len(cases) != 36
            or len({c["case_id"] for c in cases}) != 36
            or Counter(c["world_truth"] for c in cases) != {"BENIGN": 12, "ESCALATE": 16, "INCONCLUSIVE": 8}
            or Counter(c["family"] for c in cases) != {k: 6 for k in ("network", "travel", "mfa", "failures", "resource", "telemetry")}):
        raise ValueError("heldout_label_shape_or_denominators")
    strata = {"ESCALATE": {"MEDIUM": 4, "HIGH": 8, "CRITICAL": 4},
              "BENIGN": {"LOW": 8, "MEDIUM": 4}, "INCONCLUSIVE": {"MEDIUM": 4, "HIGH": 4}}
    for truth, counts in strata.items():
        if Counter(c["reference_urgency"] for c in cases if c["world_truth"] == truth) != counts:
            raise ValueError("heldout_urgency_denominator")
    family_counts = [(4, 1, 1), (4, 1, 1), (1, 4, 1), (1, 4, 1), (1, 4, 1), (1, 2, 3)]
    for family, counts in zip(("network", "travel", "mfa", "failures", "resource", "telemetry"), family_counts):
        if tuple(sum(c["family"] == family and c["world_truth"] == t for c in cases)
                 for t in ("BENIGN", "ESCALATE", "INCONCLUSIVE")) != counts:
            raise ValueError("heldout_family_denominator")
    for case in cases:
        if (set(case) != set(props) or not re.fullmatch(r"held-[0-9]{3}", case["case_id"])
                or not re.fullmatch(r"case-[0-9]{3}\.json", case["fixture"])
                or case["allowed_dispositions"] != [case["world_truth"]]
                or case["allowed_urgencies"] != [case["reference_urgency"]]
                or not case["required_evidence_rationale"]):
            raise ValueError("heldout_adjudication_shape")
        source = snapshots[case["case_id"]]
        rows = {r["id"]: r for r in source["records"]}
        if source["case_id"] != case["case_id"] or source["fictional"] is not True:
            raise ValueError("heldout_source_identity")
        for item in case["acceptable_evidence_tuples"]:
            row = rows.get(item["record_id"])
            if not row or not _supported_claim(item, row):
                raise ValueError("heldout_fact_tuple_mismatch")
        for group in case["required_evidence_groups"]:
            if (set(group) != {"purpose", "alternatives"} or not group["purpose"] or not group["alternatives"]
                    or any(not alternative or set(alternative) - rows.keys() for alternative in group["alternatives"])):
                raise ValueError("heldout_evidence_group")
        if set(case["coverage_requirements"]) != {"auth", "resource"} or any(
                type(value) is not bool for value in case["coverage_requirements"].values()):
            raise ValueError("heldout_coverage_shape")
        gaps = [r["id"] for r in source["records"] if r["kind"] == "coverage" and not r["data"]["complete"]]
        if sorted(case["required_gaps"]) != sorted(gaps):
            raise ValueError("heldout_gap_rationale")
        proposal = case["expected_proposal"]
        if (proposal is not None) != (case["world_truth"] == "ESCALATE"):
            raise ValueError("heldout_target_disposition")
        if proposal:
            row = rows.get(proposal["target_record_id"])
            if (not row or row["kind"] != "auth" or row["data"]["outcome"] != "success"
                    or proposal["action"] != "REVOKE_SESSION"
                    or row["data"]["session_id"] != proposal["target_session_id"]
                    or row["version"] != proposal["target_record_version"]
                    or proposal["target_session_id"] in case["forbidden_targets"]):
                raise ValueError("heldout_target_linkage")
    if rubric["gates"]["minimum_correct_dispositions"] != 31 or rubric["gates"]["baseline_uplift_required"]:
        raise ValueError("heldout_rubric_changed")


def manifest():
    development = check_development()
    labels = json.loads((ROOT / "evaluation/labels/heldout-v1.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "evaluation/label_schema_v2.json").read_text(encoding="utf-8"))
    rubric = json.loads((ROOT / "evaluation/heldout_rubric_v1.json").read_text(encoding="utf-8"))
    snapshots = {c["case_id"]: json.loads((ROOT / "fixtures/heldout" / c["fixture"]).read_text(encoding="utf-8"))
                 for c in labels["cases"]}
    validate_labels(labels, schema, snapshots, rubric)
    paths = sorted(FROZEN + ["fixtures/heldout/" + c["fixture"] for c in labels["cases"]])
    files = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    return {"schema_version": 1, "dataset_version": "heldout-v1", "split": "heldout",
            "status": "frozen_pending_independent_rubric_review", "scored_when_frozen": False,
            "unique_cases": 36, "planned_case_executions": 216,
            "case_ids": sorted(snapshots), "preserved_development_freeze": development["manifest_digest"],
            "accepted_m2_source_commit": "e04254caf4e7906fe32a1b1fb5700b60349a3e13",
            "files": files, "manifest_digest": _hash(files)}


def check_freeze():
    saved = json.loads((ROOT / "evaluation/heldout-v1-freeze.json").read_text(encoding="utf-8"))
    if saved != manifest():
        raise ValueError("heldout_freeze_changed_use_new_version")
    return saved


def validate_review_receipt(receipt, freeze):
    if (not isinstance(receipt, dict) or set(receipt) != {"schema_version", "dataset_version", "status", "freeze_digest", "reviewed_by",
                       "reviewed_at", "reviewed_case_ids", "notes"}
            or receipt["schema_version"] != 1 or receipt["dataset_version"] != "heldout-v1"
            or receipt["status"] != "approved" or receipt["freeze_digest"] != freeze["manifest_digest"]
            or not isinstance(receipt["reviewed_case_ids"], list)
            or sorted(receipt["reviewed_case_ids"]) != freeze["case_ids"]
            or not isinstance(receipt["reviewed_by"], str) or not receipt["reviewed_by"].strip()
            or not isinstance(receipt["notes"], list) or not receipt["notes"]
            or not all(isinstance(note, str) and note.strip() for note in receipt["notes"])
            or not isinstance(receipt["reviewed_at"], str)):
        raise ValueError("independent_rubric_review_required_before_heldout_run_or_score")
    when = datetime.fromisoformat(receipt["reviewed_at"].replace("Z", "+00:00"))
    if when.tzinfo is None or when > datetime.now(timezone.utc):
        raise ValueError("invalid_rubric_review_time")
    return receipt


def require_review(freeze, path=None):
    path = Path(path) if path else ROOT / "evaluation/heldout_review.json"
    return validate_review_receipt(json.loads(path.read_text(encoding="utf-8")), freeze)


def main():
    parser = argparse.ArgumentParser(description="Static heldout freeze; no actor or score execution.")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--require-review", action="store_true")
    parser.add_argument("--review-receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.write:
            path = ROOT / "evaluation/heldout-v1-freeze.json"
            if path.exists():
                raise ValueError("heldout_freeze_exists")
            result = manifest()
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        else:
            result = check_freeze()
        if args.require_review:
            require_review(result, args.review_receipt)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print("heldout static check failed: " + str(exc))
        return 1
    print(json.dumps({"manifest_digest": result["manifest_digest"], "unique_cases": 36,
                      "outcomes_scored": False, "independent_review_required": not args.require_review}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
