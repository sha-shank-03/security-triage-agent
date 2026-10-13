"""Versioned worker-exposed inputs/labels. No main-held/unseen set interface."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from .verify import VerificationError, _check, _hash, _time

ROOT = Path(__file__).resolve().parents[1]
VERSION = "worker-exposed-u2b-v1"
EVAL_MANIFEST = "evaluation/upgrade_eval_manifest_v3.json"
FAMILIES = ("legitimate-login", "observed-misuse", "positive-misuse-with-gaps",
            "unresolved-telemetry", "unrelated-identity-session", "stale-paged-drifted-review")


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def semantic_digest(source):
    """Ignore identifiers/absolute dates, retain relationships/facts/time offsets."""
    data = json.loads(json.dumps(source))
    data.pop("case_id")
    origin = _time(source["window_start"])
    mappings = {k: {source["alert"][k]: k + "-0"} for k in ("user_id", "device_id", "session_id", "ip")}
    times = {"window_start", "cutoff", "event_time", "ingested_at", "valid_from", "valid_to", "from", "to"}
    def normalize(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == "id": continue
                if key in mappings:
                    table = mappings[key]
                    if item not in table: table[item] = key + "-" + str(len(table))
                    result[key] = table[item]
                elif key in times:
                    result[key] = (_time(item) - origin).total_seconds()
                else: result[key] = normalize(item)
            return result
        if isinstance(value, list): return [normalize(v) for v in value]
        return value
    return _hash(normalize(data))


def input_manifest(split, root=ROOT):
    _check(split in ("development", "capability"), "no acceptance/unseen split available")
    value = json.loads((root / f"evaluation/upgrade_sets/{split}-v1.inputs.json").read_text())
    _check(value["version"] == VERSION and value["split"] == split and value["exposure"] == "worker-exposed"
           and len(value["cases"]) == 12, "input version/count/exposure")
    _check(Counter(c["family"] for c in value["cases"]) == Counter({f: 2 for f in FAMILIES}), "family counts")
    ids = [c["case_id"] for c in value["cases"]]
    _check(len(set(ids)) == 12, "duplicate input case")
    for item in value["cases"]:
        expected = f"fixtures/upgrade/{split}/{item['case_id']}.json"
        _check(item["file"] == expected and item["case_id"].startswith("u2b-") and "/" not in item["case_id"], "input path")
        path = root / expected
        _check(file_sha(path) == item["sha256"], "input mutation")
    return value


def load_inputs(split, root=ROOT):
    """Runner loads inputs only. It neither reads nor returns label/evaluator data."""
    manifest = input_manifest(split, root)
    return manifest, [(item, json.loads((root / item["file"]).read_text())) for item in manifest["cases"]]


def load_labels(split, root=ROOT):
    inputs = input_manifest(split, root)
    path = root / f"evaluation/upgrade_sets/{split}-v1.labels.json"
    labels = json.loads(path.read_text())
    _check(labels["version"] == VERSION and labels["split"] == split and labels["exposure"] == "worker-exposed"
           and labels["inputs_sha256"] == file_sha(root / f"evaluation/upgrade_sets/{split}-v1.inputs.json"), "label version/binding")
    _check({c["case_id"] for c in labels["cases"]} == {c["case_id"] for c in inputs["cases"]}
           and len(labels["cases"]) == 12, "label denominator")
    return labels


def verify_dataset(root=ROOT):
    freeze = json.loads((root / EVAL_MANIFEST).read_text())
    _check(freeze["version"] == VERSION and freeze["counts"] == {"development": 12, "capability": 12}, "dataset revision/count")
    for name, expected in freeze["files"].items():
        _check(file_sha(root / name) == expected, "dataset/label/source pin mutation")
    sources = []
    for split in ("development", "capability"):
        inputs, rows = load_inputs(split, root)
        load_labels(split, root)
        for item, source in rows:
            _check(source["case_id"] == item["case_id"] and source["fictional"] is True, "fixture identity/provenance")
            _check(semantic_digest(source) == item["semantic_sha256"], "semantic pin")
            sources.append(source)
    _check(len({s["case_id"] for s in sources}) == 24 and len({semantic_digest(s) for s in sources}) == 24, "duplicate task")
    return {"version": VERSION, "worker_exposed_tasks": 24, "counts": freeze["counts"], "semantic_duplicates": 0,
            "files_verified": len(freeze["files"]), "unseen_tasks": 0, "evaluation_executed": False}


def main():
    parser = argparse.ArgumentParser(description="Verify authored input/label/source pins; no actor execution")
    parser.add_argument("--verify", action="store_true", required=True)
    args = parser.parse_args()
    try: result = verify_dataset()
    except (VerificationError, OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"passed": False, "reason": "upgrade_dataset_verification_failed"})); return 1
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
