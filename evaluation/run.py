"""Parent harness for unchanged development diagnostics or reviewed heldout repeats."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from .freeze import check_freeze

ROOT = Path(__file__).resolve().parents[1]


def run(output, providers, repeat, split="development", review_receipt=None):
    if split == "heldout":
        from .heldout_run import run as run_heldout
        return run_heldout(output, providers, repeat, review_receipt)
    if split != "development":
        raise ValueError("unknown_evaluation_split")
    if providers != ["scripted", "baseline"] or repeat != 1:
        raise ValueError("M2 authorizes development diagnostics for both providers once")
    freeze = check_freeze()
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise ValueError("evaluation_output_exists_use_fresh_directory")
    manifest = {"schema_version": 1, "split": "development", "purpose": "diagnostic_only_not_heldout",
                "freeze_digest": freeze["manifest_digest"], "executions": [], "complete": False}
    deadline = time.monotonic() + 180
    try:
        for provider in providers:
            relative = provider + "-repeat-1"
            cmd = [sys.executable, "-m", "security_triage", "investigate-suite", "--split", "development",
                   "--provider", provider, "--request-id", "development-repeat-1", "--out", str(output / relative)]
            started = time.monotonic()
            remaining = deadline - started
            if remaining <= 0:
                raise TimeoutError("evaluation_parent_deadline")
            result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                                    encoding="utf-8", timeout=remaining, check=False)
            manifest["executions"].append({"provider": provider, "repeat": 1, "directory": relative,
                "command": [p if p != str(output / relative) else relative for p in cmd[1:]],
                "exit_code": result.returncode, "wall_seconds": time.monotonic() - started,
                "stdout": result.stdout[-16384:], "stderr": result.stderr[-16384:]})
            if result.returncode:
                raise ValueError("actor_subprocess_failed")
        manifest["complete"] = True
    finally:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Development diagnostics or independently reviewed heldout repeats.")
    parser.add_argument("--split", choices=["development", "heldout"], required=True)
    parser.add_argument("--providers", default="scripted,baseline")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.out, args.providers.split(","), args.repeat, args.split, args.review_receipt)
    except (ValueError, OSError, subprocess.SubprocessError, TimeoutError) as exc:
        print("evaluation run failed: " + str(exc))
        return 1
    print(json.dumps({"split": result["split"], "executions": len(result["executions"]),
                      "diagnostic_only": result["split"] == "development"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
