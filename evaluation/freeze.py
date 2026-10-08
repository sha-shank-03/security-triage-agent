"""Static development freeze verification. Never runs actors or scores outcomes."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN_PATHS = ["docs/BASELINE.md", "security_triage/baseline.py", "security_triage/providers.py",
                "evaluation/label_schema.json", "evaluation/labels/development.json"]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def freeze_manifest():
    labels = json.loads((ROOT / "evaluation/labels/development.json").read_text(encoding="utf-8"))
    cases = labels["cases"]
    if (labels["schema_version"] != 1 or labels["split"] != "development"
            or labels["purpose"] != "diagnostic_only_not_heldout" or len(cases) != 12
            or len({c["case_id"] for c in cases}) != 12
            or Counter(c["world_truth"] for c in cases) != {"BENIGN": 4, "ESCALATE": 4, "INCONCLUSIVE": 4}
            or set(Counter(c["family"] for c in cases).values()) != {2}):
        raise ValueError("invalid_development_label_denominators")
    schema = json.loads((ROOT / "evaluation/label_schema.json").read_text(encoding="utf-8"))
    required = set(schema["properties"]["cases"]["items"]["required"])
    for case in cases:
        if set(case) != required or case["world_truth"] not in case["allowed_dispositions"]:
            raise ValueError("invalid_label_shape")
        if not case["allowed_urgencies"] or not case["required_evidence_rationale"]:
            raise ValueError("missing_adjudication")
        if (case["expected_proposal"] is not None) != (case["world_truth"] == "ESCALATE"):
            raise ValueError("label_target_disposition_mismatch")
        path = "fixtures/development/" + case["fixture"]
        source = json.loads((ROOT / path).read_text(encoding="utf-8"))
        if source["case_id"] != case["case_id"]:
            raise ValueError("fixture_label_case_mismatch")
    paths = FROZEN_PATHS + ["fixtures/development/" + c["fixture"] for c in cases]
    files = {path: sha((ROOT / path).read_bytes()) for path in sorted(paths)}
    serialized = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"schema_version": 1, "split": "development", "status": "frozen_before_first_scoring",
            "baseline": "fixed_six_reads_v1", "unique_cases": 12, "scored_when_frozen": False,
            "files": files, "manifest_digest": sha(serialized)}


def check_freeze():
    current = freeze_manifest()
    saved = json.loads((ROOT / "evaluation/development_freeze.json").read_text(encoding="utf-8"))
    if saved != current:
        raise ValueError("development_freeze_changed")
    return saved


def main():
    parser = argparse.ArgumentParser(description="Freeze static source/spec/labels before development scoring.")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        if args.write:
            path = ROOT / "evaluation/development_freeze.json"
            if path.exists():
                raise ValueError("freeze_already_exists")
            result = freeze_manifest()
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        else:
            result = check_freeze()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("static freeze failed: " + str(exc))
        return 1
    print(json.dumps({"manifest_digest": result["manifest_digest"], "unique_cases": 12,
                      "baseline": result["baseline"], "outcomes_scored": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
