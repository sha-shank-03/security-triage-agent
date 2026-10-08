"""Owned crash injector for deferred integration; starts only via explicit command."""

import argparse
import os
from pathlib import Path

from security_triage.contracts import Budget, strict_json
from security_triage.loop import investigate
from security_triage.providers import ScriptedInvestigator
from security_triage.store import EvidenceStore, RunStore, create_evidence

ROOT = Path(__file__).resolve().parents[1]


class CrashAfterObservation:
    name = ScriptedInvestigator.name
    configuration = ScriptedInvestigator.configuration

    def next_turn(self, conversation, catalog, remaining):
        if any(m["role"] == "tool" for m in conversation):
            os._exit(73)  # Owned test process only; reservation is already durable.
        return ScriptedInvestigator().next_turn(conversation, catalog, remaining)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    snapshot = strict_json((ROOT / "fixtures/demo/case-002.json").read_text(encoding="utf-8"))
    create_evidence(args.out / "evidence.sqlite", [snapshot])
    evidence = EvidenceStore(args.out / "evidence.sqlite", snapshot["case_id"])
    runs = RunStore(args.out / "runs.sqlite")
    try:
        investigate(evidence, runs, CrashAfterObservation(), Budget(max_turns=3), request_id="recovery")
    finally:
        evidence.close()
        runs.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
