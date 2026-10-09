"""Reviewed heldout parent harness: six sequential actor subprocesses, no labels passed."""

import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from .heldout_freeze import check_freeze, require_review
from .verify import _hash

ROOT = Path(__file__).resolve().parents[1]


def actor_command(provider, repeat, output):
    return [sys.executable, "-m", "security_triage", "investigate-suite", "--split", "heldout",
            "--provider", provider, "--request-id", "heldout-repeat-" + str(repeat), "--out", str(output)]


def completed_ids(directory):
    path = directory / "runs.sqlite"
    if not path.is_file():
        return []
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return [r[0] for r in db.execute("SELECT case_id FROM runs WHERE state='COMPLETED'")]
    finally:
        db.close()


def text(value):
    return (value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or "")[-16384:]


def run(output, providers, repeat, review_receipt=None):
    if providers != ["scripted", "baseline"] or repeat != 3:
        raise ValueError("heldout_requires_both_frozen_scripts_three_repeats")
    freeze = check_freeze()
    review = require_review(freeze, review_receipt)
    # Reviewed labels are available only to this parent; actors receive fixed input split and configuration.
    case_ids = freeze["case_ids"]
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise ValueError("evaluation_output_exists_use_fresh_directory")
    planned = [(provider, iteration) for provider in providers for iteration in range(1, 4)]
    manifest = {"schema_version": 2, "split": "heldout", "dataset_version": "heldout-v1",
        "freeze_digest": freeze["manifest_digest"], "review_digest": _hash(review),
        "unique_cases": 36, "planned_case_executions": 216, "repeat": 3,
        "executions": [], "unexecuted": [], "complete": False, "parent_deadline_seconds": 180}
    deadline = time.monotonic() + 180
    try:
        for index, (provider, iteration) in enumerate(planned):
            relative = provider + "-repeat-" + str(iteration)
            directory = output / relative
            command = actor_command(provider, iteration, directory)
            started = time.monotonic()
            record = {"provider": provider, "repeat": iteration, "directory": relative,
                      "exit_code": None, "status": "unexecuted", "stdout": "", "stderr": ""}
            try:
                remaining = deadline - started
                if remaining <= 0:
                    raise TimeoutError("evaluation_parent_deadline")
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                                        timeout=remaining, check=False)
                record.update(exit_code=result.returncode, stdout=text(result.stdout), stderr=text(result.stderr),
                              status="completed" if result.returncode == 0 else "failed")
            except subprocess.TimeoutExpired as exc:
                record.update(status="timed_out", stdout=text(exc.stdout), stderr=text(exc.stderr))
                raise
            finally:
                record["wall_seconds"] = time.monotonic() - started
                record["completed_case_ids"] = sorted(completed_ids(directory))
                manifest["executions"].append(record)
                missing = sorted(set(case_ids) - set(record["completed_case_ids"]))
                if missing:
                    manifest["unexecuted"].append({"provider": provider, "repeat": iteration, "case_ids": missing})
            if record["exit_code"] != 0 or len(record["completed_case_ids"]) != 36:
                raise ValueError("actor_subprocess_failed_or_incomplete")
        manifest["complete"] = True
    finally:
        done = {(e["provider"], e["repeat"]) for e in manifest["executions"]}
        for provider, iteration in planned:
            if (provider, iteration) not in done:
                manifest["unexecuted"].append({"provider": provider, "repeat": iteration, "case_ids": case_ids})
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
