"""Offline investigations and exact-content SIMULATED local review."""

import argparse
import json
import sqlite3
from pathlib import Path

from .baseline import FixedBaseline
from .contracts import ContractError, strict_json
from .loop import investigate
from .ollama import OllamaProvider
from .providers import ScriptedInvestigator
from .reports import write_reports
from .review import review_proposal
from .store import EvidenceStore, RunStore, create_evidence

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "demo"


def run_snapshots(snapshots, output, provider, *, resume=False, request_id="default"):
    output.mkdir(parents=True, exist_ok=True)
    create_evidence(output / "evidence.sqlite", snapshots)
    runs = RunStore(output / "runs.sqlite")
    try:
        for snapshot in snapshots:
            evidence = EvidenceStore(output / "evidence.sqlite", snapshot["case_id"])
            try:
                investigate(evidence, runs, provider, resume=resume, request_id=request_id)
            finally:
                evidence.close()
        return write_reports(runs, output)
    finally:
        runs.close()


def demo(output):
    snapshots = [strict_json(path.read_text(encoding="utf-8")) for path in sorted(FIXTURES.glob("*.json"))]
    if len(snapshots) != 3:
        raise ContractError("demo_requires_three_fixtures")
    return run_snapshots(snapshots, output, ScriptedInvestigator())


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fictional triage; no containment executor.")
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("demo")
    cmd.add_argument("--out", type=Path, required=True)
    for name in ("investigate-case", "investigate-suite"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--out", type=Path, required=True)
        cmd.add_argument("--provider", choices=["scripted", "baseline"] + (["ollama"] if name.endswith("case") else []),
                         default="scripted")
        cmd.add_argument("--resume", action="store_true")
        cmd.add_argument("--request-id", default="default")
        if name.endswith("case"):
            cmd.add_argument("--fixture", type=Path, required=True)
            cmd.add_argument("--model")
            cmd.add_argument("--port", type=int, default=11434)
        else:
            cmd.add_argument("--split", choices=["development", "heldout"], required=True)
    cmd = commands.add_parser("review", help="Record SIMULATED approval/rejection; execute nothing.")
    cmd.add_argument("--db", type=Path, required=True)
    cmd.add_argument("--proposal-id", required=True)
    cmd.add_argument("--expected-version", type=int, required=True)
    cmd.add_argument("--expected-hash", required=True)
    cmd.add_argument("--decision", choices=["approve", "reject"], required=True)
    cmd.add_argument("--reviewer", required=True)
    cmd.add_argument("--request-id", required=True)
    cmd = commands.add_parser("cancel")
    cmd.add_argument("--db", type=Path, required=True)
    cmd.add_argument("--run-id", required=True)
    cmd = commands.add_parser("register-snapshot", help="Register a separately stored newer fictional snapshot.")
    cmd.add_argument("--db", type=Path, required=True)
    cmd.add_argument("--evidence-db", type=Path, required=True)
    cmd.add_argument("--case-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("review", "cancel", "register-snapshot"):
            if not args.db.is_file():
                raise ContractError("missing_workflow_database")
            runs = RunStore(args.db)
            try:
                if args.command == "review":
                    result = review_proposal(runs, args.proposal_id, args.expected_hash,
                                             args.expected_version, args.decision, args.reviewer, args.request_id)
                elif args.command == "cancel":
                    runs.request_cancel(args.run_id)
                    result = {"run_id": args.run_id, "state": "CANCEL_REQUESTED"}
                else:
                    evidence = EvidenceStore(args.evidence_db, args.case_id)
                    try:
                        runs.register_snapshot(evidence)
                        result = {"case_id": args.case_id, "snapshot_digest": evidence.snapshot_digest}
                    finally:
                        evidence.close()
            finally:
                runs.close()
            print(json.dumps(result, indent=2))
            print("Containment: NOT_IMPLEMENTED. Review is SIMULATED.")
            return 0
        if args.command == "demo":
            packet = demo(args.out)
        else:
            provider = (ScriptedInvestigator() if args.provider == "scripted" else
                        FixedBaseline() if args.provider == "baseline" else OllamaProvider(args.model, args.port))
            paths = ([args.fixture] if args.command == "investigate-case" else
                     sorted((ROOT / "fixtures" / args.split).glob("*.json")))
            snapshots = [strict_json(path.read_text(encoding="utf-8")) for path in paths]
            if args.command == "investigate-suite" and len(snapshots) != {"development": 12, "heldout": 36}[args.split]:
                raise ContractError("suite_fixture_count_mismatch")
            packet = run_snapshots(snapshots, args.out, provider, resume=args.resume, request_id=args.request_id)
        print("Mode: " + packet["mode"] + "; fictional data.")
        for case in packet["cases"]:
            final = case["final"]
            print(case["case_id"] + ": " + (final["disposition"] + " / " + final["urgency"] if final else case["state"]))
        print("Reports: " + str(args.out / "report.md") + " and " + str(args.out / "results.json"))
        print("Containment: NOT_IMPLEMENTED. Review is SIMULATED.")
        return 0
    except (ContractError, OSError, sqlite3.Error, ValueError, TypeError) as exc:
        print("command failed: " + str(exc))
        return 2

