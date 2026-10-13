"""Authored bounded worker-exposed run harness. Does not load labels or score."""

import argparse
import json
import signal
import time
from pathlib import Path

from security_triage.complete_playbook import PlaybookTransport, VERSION as BASELINE_VERSION
from security_triage.gateway import GatewayConfig
from security_triage.store import EvidenceStore, create_evidence
from security_triage.upgrade import code_digest, export, run_case
from security_triage.upgrade_runtime import investigate
from security_triage.upgrade_state import UpgradeState

from .upgrade_dataset import EVAL_MANIFEST, ROOT, VERSION, file_sha, load_inputs


def run_baseline(source, out, config):
    out.mkdir(parents=True, exist_ok=False)
    create_evidence(out / "evidence.sqlite", [source])
    evidence = EvidenceStore(out / "evidence.sqlite", source["case_id"])
    state = UpgradeState(out / "state.sqlite")
    transport = PlaybookTransport()
    prior = signal.getsignal(signal.SIGINT)
    def cancel(_signum, _frame):
        if state.run_id: state.request_cancel()
    signal.signal(signal.SIGINT, cancel)
    try:
        investigate(evidence, state, config, transport, code_sha256=code_digest())
        with state.db:
            state.event("baseline_contract", {"provider": "complete-playbook-v2", "policy_version": BASELINE_VERSION,
                        "policy_sha256": file_sha(ROOT / "security_triage/complete_playbook.py"),
                        "genuine_model": False, "authority": "read-only"})
        return export(state, out, transport.last_cleanup)
    finally:
        signal.signal(signal.SIGINT, prior)
        evidence.close(); state.close()


def run(split, providers, out, max_seconds=180, demo_case=None):
    if (split not in ("development", "capability") or not providers or len(providers) > 2 or len(set(providers)) != len(providers)
            or set(providers) - {"complete-playbook-v2", "gateway-double"} or type(max_seconds) is not int or not 1 <= max_seconds <= 300):
        raise ValueError("invalid_worker_exposed_batch")
    if out.exists(): raise ValueError("use_fresh_output_directory")
    inputs, sources = load_inputs(split)
    if demo_case is not None:
        sources = [(item, source) for item, source in sources if source["case_id"] == demo_case]
        if len(sources) != 1: raise ValueError("demo_case_not_in_input_manifest")
    out.mkdir(parents=True)
    config = GatewayConfig()
    started = time.monotonic()
    manifest = {"version": VERSION, "split": split, "suite": "demo" if demo_case else "split", "exposure": "worker-exposed", "providers": providers,
        "input_manifest_sha256": file_sha(ROOT / f"evaluation/upgrade_sets/{split}-v1.inputs.json"),
        "eval_manifest_sha256": file_sha(ROOT / EVAL_MANIFEST),
        "code_sha256": code_digest(), "configuration": config.public(), "max_batch_seconds": max_seconds,
        "complete": False, "executions": [{"case_id": source["case_id"], "provider": provider,
        "directory": source["case_id"] + "--" + provider, "fixture_sha256": item["sha256"],
        "status": "PENDING", "execution_wall_seconds": None, "actual_cost_minor_units": None,
        "cost_currency": "INR", "paid_model_calls": 0,
        "mode": "SCRIPTED_BASELINE" if provider == "complete-playbook-v2" else "LOCAL_DOUBLE"}
        for item, source in sources for provider in providers], "labels_loaded": False, "unseen_tasks": 0}
    def save(): (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    save()
    exhausted = False
    for item, source in sources:
        for provider in providers:
            name = source["case_id"] + "--" + provider
            entry = next(e for e in manifest["executions"] if e["directory"] == name)
            if exhausted or time.monotonic() - started >= max_seconds:
                entry["reason"] = "batch_stopped_unexecuted"; exhausted = True; save(); continue
            entry.update(status="STARTED", reason="case_started_no_terminal_receipt")
            save()
            began = time.monotonic()
            try:
                packet = run_baseline(source, out / name, config) if provider == "complete-playbook-v2" else run_case(
                    ROOT / item["file"], out / name, config, scenario="branch-after-observation")
                entry.update(status=packet["run"]["state"], reason=packet["outcome"]["reason"],
                             packet_sha256=file_sha(out / name / "packet.json"),
                             state_sha256=file_sha(out / name / "state.sqlite"), evidence_sha256=file_sha(out / name / "evidence.sqlite"))
                if packet["run"]["state"] == "CANCELLED": exhausted = True
            except Exception:
                entry.update(status="FAILED", reason="execution_failed_retained_artifacts")
            finally:
                entry["execution_wall_seconds"] = time.monotonic() - began
                save()
    manifest["complete"] = all(e["status"] not in ("PENDING", "STARTED", "FAILED") for e in manifest["executions"])
    manifest["batch_wall_seconds"] = time.monotonic() - started
    save()
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Local only; no labels, live model, credentials or write authority")
    parser.add_argument("--split", choices=["development", "capability"], required=True)
    parser.add_argument("--providers", default="complete-playbook-v2,gateway-double")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-seconds", type=int, default=180)
    parser.add_argument("--demo-case", help="One manifest-approved case; demo is not a scored split")
    args = parser.parse_args()
    try: result = run(args.split, args.providers.split(","), args.out, args.max_seconds, args.demo_case)
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({"passed": False, "reason": "batch_setup_failed"})); return 1
    print(json.dumps({"complete": result["complete"], "cases": len(result["executions"]), "mode": "local_worker_exposed"}))
    return 0 if result["complete"] else 2


if __name__ == "__main__": raise SystemExit(main())
