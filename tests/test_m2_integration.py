"""Deferred M2 checks: full loops, disk persistence, owned subprocess and HTTP double."""

import copy
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_triage.contracts import Budget, ContractError, canonical, strict_json
from security_triage.loop import investigate
from security_triage.ollama import OllamaProvider
from security_triage.providers import ScriptedInvestigator
from security_triage.review import ReviewError, review_proposal
from security_triage.store import EvidenceStore, RunStore, create_evidence
from tests.http_double import protocol_double

ROOT = Path(__file__).resolve().parents[1]


def fixture(number=2):
    return strict_json((ROOT / "fixtures/demo" / f"case-{number:03}.json").read_text(encoding="utf-8"))


def response(tool, arguments=None):
    return {"done": True, "message": {"role": "assistant", "content": "",
            "tool_calls": [{"type": "function", "function": {"name": tool, "arguments": arguments or {}}}]}}


class M2Integration(unittest.TestCase):
    def setUp(self):
        (ROOT / "work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m2-integration-", dir=ROOT / "work")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def stores(self, snapshot=None, clock=None):
        snapshot = snapshot or fixture()
        create_evidence(self.root / "evidence.sqlite", [snapshot])
        evidence = EvidenceStore(self.root / "evidence.sqlite", snapshot["case_id"])
        runs = RunStore(self.root / "runs.sqlite", **({"clock": clock} if clock else {}))
        return evidence, runs

    def test_review_duplicate_delivery_no_source_mutation_and_reopen(self):
        evidence, runs = self.stores()
        try:
            investigate(evidence, runs, ScriptedInvestigator())
            proposal, payload_hash = runs.db.execute("SELECT proposal_id,payload_hash FROM proposals").fetchone()
            original = hashlib.sha256((self.root / "evidence.sqlite").read_bytes()).hexdigest()
            result = review_proposal(runs, proposal, payload_hash, 1, "approve", "analyst-demo", "delivery")
            runs.close()
            runs = RunStore(self.root / "runs.sqlite")
            repeated = review_proposal(runs, proposal, payload_hash, 1, "approve", "analyst-demo", "delivery")
            self.assertEqual(result, repeated)
            self.assertEqual(result["state"], "APPROVED_SIMULATION")
            self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0], 1)
            self.assertEqual(original, hashlib.sha256((self.root / "evidence.sqlite").read_bytes()).hexdigest())
            with self.assertRaisesRegex(ReviewError, "request_id_conflict"):
                review_proposal(runs, proposal, payload_hash, 1, "reject", "analyst-demo", "delivery")
        finally:
            evidence.close()
            runs.close()

    def test_new_snapshot_and_expiry_refuse_review(self):
        for mode in ("snapshot", "expiry"):
            with self.subTest(mode=mode):
                folder = self.root / mode
                folder.mkdir()
                snapshot = fixture()
                create_evidence(folder / "evidence.sqlite", [snapshot])
                evidence = EvidenceStore(folder / "evidence.sqlite", snapshot["case_id"])
                now = [datetime(2026, 10, 8, 10, 30, tzinfo=timezone.utc)]
                runs = RunStore(folder / "runs.sqlite", clock=lambda: now[0])
                try:
                    investigate(evidence, runs, ScriptedInvestigator())
                    proposal, payload_hash = runs.db.execute("SELECT proposal_id,payload_hash FROM proposals").fetchone()
                    if mode == "snapshot":
                        changed = copy.deepcopy(snapshot)
                        changed["snapshot_version"] = 2
                        next(r for r in changed["records"] if r["kind"] == "identity")["version"] = 2
                        create_evidence(folder / "new-evidence.sqlite", [changed])
                        newer = EvidenceStore(folder / "new-evidence.sqlite", changed["case_id"])
                        try:
                            runs.register_snapshot(newer)
                        finally:
                            newer.close()
                    else:
                        now[0] += timedelta(hours=24)
                    with self.assertRaises(ReviewError):
                        review_proposal(runs, proposal, payload_hash, 1, "approve", "analyst-demo", "delivery")
                    self.assertEqual(runs.db.execute("SELECT state FROM proposals").fetchone()[0],
                                     "STALE" if mode == "snapshot" else "EXPIRED")
                finally:
                    evidence.close()
                    runs.close()

    def test_owned_crash_resume_does_not_restore_turns_or_deadline(self):
        folder = self.root / "recovery"
        result = subprocess.run([sys.executable, "-m", "tests.recovery_child", "--out", str(folder)],
                                cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 73, result.stderr)
        evidence = EvidenceStore(folder / "evidence.sqlite", "demo-002")
        runs = RunStore(folder / "runs.sqlite")
        try:
            saved = runs.db.execute("SELECT run_id,turns_used,expires_at FROM runs").fetchone()
            self.assertEqual(saved[1], 2)
            self.assertEqual(runs.history(saved[0])[-1][3], "REQUEST_STARTED")
            with self.assertRaisesRegex(ContractError, "explicit_resume"):
                investigate(evidence, runs, ScriptedInvestigator(), Budget(max_turns=3), request_id="recovery")
            run = investigate(evidence, runs, ScriptedInvestigator(), Budget(max_turns=3),
                              request_id="recovery", resume=True)
            state = runs.state(run)
            self.assertEqual(state["turns_used"], 3)
            self.assertEqual(state["expires_at"], saved[2])
            final = json.loads(runs.db.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run,)).fetchone()[0])
            self.assertEqual(final["disposition"], "INCONCLUSIVE")
            self.assertEqual(final["stop_reason"], "turn_budget_exhausted")
            self.assertEqual(runs.history(run)[1][3], "provider_request_interrupted")
            self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 0)
        finally:
            evidence.close()
            runs.close()

    def test_real_loopback_wire_continues_with_native_assistant_and_tool_messages(self):
        # Two actual HTTP calls, no inference. Full provider loop ends at the turn bound.
        with protocol_double([(200, response("get_identity_context")),
                              (200, response("search_events", {"kind": "auth"}))]) as (port, observed):
            evidence, runs = self.stores()
            provider = OllamaProvider("protocol-fixture", port, protocol_double=True)
            try:
                run = investigate(evidence, runs, provider, Budget(max_turns=2))
                self.assertEqual(len(observed), 2)
                roles = [m["role"] for m in observed[1]["messages"]]
                self.assertEqual(roles[-2:], ["assistant", "tool"])
                self.assertEqual(observed[1]["messages"][-1]["tool_name"], "get_identity_context")
                self.assertEqual(runs.state(run)["config"]["provider"]["mode"], "protocol_double")
                self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 2)
                final = json.loads(runs.db.execute("SELECT final_json FROM dispositions").fetchone()[0])
                self.assertEqual(final["stop_reason"], "turn_budget_exhausted")
                self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 0)
            finally:
                evidence.close()
                runs.close()

    def test_http_retry_limit_unknown_tool_and_oversized_response_fail_bounded(self):
        scenarios = [
            ([(503, b"{}"), (503, b"{}")], "wire_retry_exhausted", 2),
            ([(200, response("execute_containment"))], "wire_unknown_tool", 1),
            ([(200, b" " * 65537)], "wire_response_byte_budget", 1),
            ([(302, b"{}")], "wire_http_status_302", 1),
        ]
        for replies, reason, count in scenarios:
            with self.subTest(reason=reason), protocol_double(replies) as (port, observed):
                provider = OllamaProvider("protocol-fixture", port, protocol_double=True)
                with self.assertRaisesRegex(ContractError, reason):
                    provider.next_turn([], [], {"seconds": 3})
                self.assertEqual(len(observed), count)
                self.assertEqual(provider.last_usage["wire_requests"], count)

    def test_provider_fault_and_mid_request_cancellation_cannot_commit_proposal(self):
        for cancellation in (False, True):
            with self.subTest(cancellation=cancellation):
                folder = self.root / ("cancel" if cancellation else "fault")
                folder.mkdir()
                snapshot = fixture()
                create_evidence(folder / "evidence.sqlite", [snapshot])
                evidence = EvidenceStore(folder / "evidence.sqlite", snapshot["case_id"])
                runs = RunStore(folder / "runs.sqlite")

                class FaultProvider:
                    name = "fault_double"
                    def next_turn(self, conversation, catalog, remaining):
                        if cancellation:
                            run = runs.db.execute("SELECT run_id FROM runs").fetchone()[0]
                            runs.request_cancel(run)
                        raise RuntimeError("owned fault")

                try:
                    run = investigate(evidence, runs, FaultProvider())
                    self.assertEqual(runs.state(run)["state"], "CANCELLED" if cancellation else "COMPLETED")
                    self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 0)
                    if cancellation:
                        self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM dispositions").fetchone()[0], 0)
                    else:
                        final = json.loads(runs.db.execute("SELECT final_json FROM dispositions").fetchone()[0])
                        self.assertEqual(final["stop_reason"], "provider_failure")
                finally:
                    evidence.close()
                    runs.close()

    def test_real_http_timeout_consumes_case_deadline_without_retry_extension(self):
        with protocol_double([(200, response("get_identity_context"), 0.15)]) as (port, observed):
            provider = OllamaProvider("protocol-fixture", port, protocol_double=True)
            started = time.monotonic()
            with self.assertRaisesRegex(ContractError, "deadline_exhausted"):
                provider.next_turn([], [], {"seconds": 0.05})
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(len(observed), 1)
            self.assertEqual(provider.last_usage["wire_requests"], 1)

    def test_source_index_corruption_fails_before_tools(self):
        snapshot = fixture()
        create_evidence(self.root / "evidence.sqlite", [snapshot])
        db = sqlite3.connect(self.root / "evidence.sqlite")
        try:
            db.execute("UPDATE records SET kind='resource' WHERE record_id='login-002'")
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(ContractError, "evidence_integrity_failure"):
            EvidenceStore(self.root / "evidence.sqlite", snapshot["case_id"])


if __name__ == "__main__":
    unittest.main()
