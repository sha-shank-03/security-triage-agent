"""Pure/component checks only: in-memory stores, injected transport, no actor loop."""

import copy
import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from security_triage.baseline import FixedBaseline
from security_triage.contracts import Budget, ContractError, canonical, digest
from security_triage.ollama import OllamaProvider, wire_request, wire_response
from security_triage.policy import claim, validate_final
from security_triage.review import ReviewError, review_proposal, validate_review
from security_triage.store import RunStore, validate_snapshot
from security_triage.tools import CATALOG, EvidenceTools

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 8, 10, 30, tzinfo=timezone.utc)


class MemoryEvidence:
    def __init__(self, number=2, snapshot=None):
        self.snapshot = snapshot or json.loads(
            (ROOT / "fixtures/demo" / f"case-{number:03}.json").read_text(encoding="utf-8"))
        self.case_id = self.snapshot["case_id"]
        self.snapshot_digest = digest(self.snapshot)

    def records(self, kind):
        return sorted([copy.deepcopy(r) for r in self.snapshot["records"] if r["kind"] == kind],
                      key=lambda r: (r["event_time"], r["id"]))


def reply(name="get_identity_context", args=None, **extra):
    return canonical({"done": True, "message": {"role": "assistant", "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": args or {}}}]}, **extra})


class PersistenceComponents(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.runs = RunStore(":memory:", clock=lambda: self.now)
        self.evidence = MemoryEvidence()

    def tearDown(self):
        self.runs.close()

    def test_reserved_turn_and_corrections_survive_explicit_resume_without_reset(self):
        budget = Budget(max_turns=2, deadline_seconds=20)
        run, _ = self.runs.start(self.evidence, "component", budget, {"model": "a"})
        t = self.runs.reserve_turn(run)
        self.runs.record(run, t, "bad", False, "malformed_json")
        self.runs.reserve_turn(run)  # Represents a committed reservation before an interrupted request.
        before = self.runs.state(run)
        with self.assertRaisesRegex(ContractError, "explicit_resume"):
            self.runs.start(self.evidence, "component", budget, {"model": "a"})
        self.runs.start(self.evidence, "component", budget, {"model": "a"}, resume=True)
        self.assertEqual(self.runs.state(run), before)
        self.assertEqual(self.runs.history(run)[-1][3], "provider_request_interrupted")
        with self.assertRaisesRegex(ContractError, "turn_budget_exhausted"):
            self.runs.reserve_turn(run)

    def test_resume_rejects_provider_budget_snapshot_and_request_changes(self):
        self.runs.start(self.evidence, "component", configuration={"model": "a"})
        variants = [
            {"configuration": {"model": "b"}},
            {"budget": Budget(max_turns=3), "configuration": {"model": "a"}},
            {"request_id": "other", "configuration": {"model": "a"}},
        ]
        for kw in variants:
            with self.subTest(kw=kw), self.assertRaisesRegex(ContractError, "resume_configuration"):
                self.runs.start(self.evidence, "component", resume=True, **kw)
        changed = copy.deepcopy(self.evidence.snapshot)
        changed["snapshot_version"] = 2
        with self.assertRaisesRegex(ContractError, "resume_configuration"):
            self.runs.start(MemoryEvidence(snapshot=changed), "component",
                            configuration={"model": "a"}, resume=True)

    def test_absolute_deadline_does_not_restart_on_resume(self):
        run, _ = self.runs.start(self.evidence, "component", Budget(deadline_seconds=1))
        expiry = self.runs.state(run)["expires_at"]
        self.now += timedelta(seconds=2)
        self.runs.start(self.evidence, "component", Budget(deadline_seconds=1), resume=True)
        self.assertEqual(self.runs.state(run)["expires_at"], expiry)
        with self.assertRaisesRegex(ContractError, "deadline_exhausted"):
            self.runs.reserve_turn(run)

    def test_snapshot_registry_refuses_rollback_or_same_version_replacement(self):
        self.runs.register_snapshot(self.evidence)
        changed = copy.deepcopy(self.evidence.snapshot)
        changed["records"][0]["version"] = 2
        with self.assertRaisesRegex(ContractError, "snapshot_version_conflict"):
            self.runs.register_snapshot(MemoryEvidence(snapshot=changed))
        changed["snapshot_version"] = 2
        self.runs.register_snapshot(MemoryEvidence(snapshot=changed))
        with self.assertRaisesRegex(ContractError, "snapshot_version_conflict"):
            self.runs.register_snapshot(self.evidence)

    def test_cancellation_is_terminal_and_blocks_commit(self):
        run, _ = self.runs.start(self.evidence, "component")
        self.runs.request_cancel(run)
        with self.assertRaisesRegex(ContractError, "run_not_active"):
            self.runs.reserve_turn(run)
        with self.assertRaisesRegex(ContractError, "run_not_active"):
            self.runs.finish(run, {"proposal": None}, self.evidence)
        self.runs.cancel(run)
        with self.assertRaisesRegex(ContractError, "cancelled_run"):
            self.runs.start(self.evidence, "component", resume=True)
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM dispositions").fetchone()[0], 0)

    def test_attempt_cannot_be_written_without_reservation_or_twice(self):
        run, _ = self.runs.start(self.evidence, "component")
        with self.assertRaisesRegex(ContractError, "attempt_not_reserved"):
            self.runs.record(run, 1, "bad", False, "malformed_json")
        t = self.runs.reserve_turn(run)
        self.runs.record(run, t, "bad", False, "malformed_json")
        with self.assertRaisesRegex(ContractError, "already_recorded"):
            self.runs.record(run, t, "bad", False, "malformed_json")
        self.assertEqual(self.runs.state(run)["corrections_used"], 1)

    def test_failed_final_transaction_leaves_no_accepted_attempt_or_disposition(self):
        run, _ = self.runs.start(self.evidence, "component")
        turn = self.runs.reserve_turn(run)
        original = self.runs._finish
        def fail_after_finish(*args):
            original(*args)
            raise sqlite3.OperationalError("owned commit fault")
        final = {"disposition": "INCONCLUSIVE", "stop_reason": "host_fallback", "proposal": None}
        with patch.object(self.runs, "_finish", side_effect=fail_after_finish):
            with self.assertRaises(sqlite3.OperationalError):
                self.runs.record(run, turn, "{}", True, "validated_finish", final=final, evidence=self.evidence)
        self.assertEqual(self.runs.history(run)[0][3], "REQUEST_STARTED")
        self.assertEqual(self.runs.state(run)["state"], "INVESTIGATING")
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM dispositions").fetchone()[0], 0)
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM audit_events WHERE event='run_completed'").fetchone()[0], 0)

    def test_persisted_correction_and_deadline_limits_gate_store_commits(self):
        run, _ = self.runs.start(self.evidence, "component", Budget(max_corrections=0, deadline_seconds=1))
        turn = self.runs.reserve_turn(run)
        self.runs.record(run, turn, "bad", False, "malformed_json")
        with self.assertRaisesRegex(ContractError, "correction_budget_exhausted"):
            self.runs.reserve_turn(run)
        self.now += timedelta(seconds=2)
        with self.assertRaisesRegex(ContractError, "deadline_exhausted"):
            self.runs.finish(run, {"proposal": None, "stop_reason": "validated_finish"}, self.evidence)
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM dispositions").fetchone()[0], 0)

    def test_deadline_requires_finite_numeric_value(self):
        for value in (True, "60", float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ContractError):
                Budget(deadline_seconds=value)


class ReviewComponents(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.runs = RunStore(":memory:", clock=lambda: self.now)
        self.evidence = MemoryEvidence()
        self.original = canonical(self.evidence.snapshot)
        run, _ = self.runs.start(self.evidence, "component")
        success = next(r for r in self.evidence.snapshot["records"] if r["id"] == "login-002")
        final = {"disposition": "ESCALATE", "urgency": "HIGH", "stop_reason": "validated_finish",
                 "claims": [claim("AUTH_SUCCESS", success)], "proposal": {"action": "REVOKE_SESSION",
                 "target_session_id": "session-002", "target_record_id": "login-002", "target_record_version": 1}}
        self.runs.finish(run, final, self.evidence)  # Tests the store component, not an investigation.
        self.proposal, self.hash, raw = self.runs.db.execute(
            "SELECT proposal_id,payload_hash,payload_json FROM proposals").fetchone()
        self.payload = json.loads(raw)

    def tearDown(self):
        self.runs.close()

    def review(self, request="review-1", decision="approve", expected_hash=None, version=1):
        return review_proposal(self.runs, self.proposal, expected_hash or self.hash,
                              version, decision, "local-reviewer", request)

    def test_simulated_approval_is_idempotent_and_preserves_source(self):
        first = self.review()
        self.now += timedelta(hours=1)
        self.assertEqual(first, self.review())
        self.assertEqual(first["state"], "APPROVED_SIMULATION")
        self.assertEqual(first["execution_status"], "NOT_IMPLEMENTED")
        self.assertEqual(canonical(self.evidence.snapshot), self.original)
        changed = copy.deepcopy(self.evidence.snapshot)
        changed["snapshot_version"] = 2
        self.runs.register_snapshot(MemoryEvidence(snapshot=changed))
        self.assertEqual(first, self.review())  # Historical replay creates no fresh approval.
        self.assertEqual(self.runs.db.execute("SELECT version FROM proposals").fetchone()[0], 2)
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0], 1)
        with self.assertRaisesRegex(ReviewError, "request_id_conflict"):
            self.review(decision="reject")
        with self.assertRaisesRegex(ReviewError, "proposal_not_pending"):
            self.review(request="review-2", version=2)

    def test_wrong_hash_and_failed_request_replay_are_recorded_without_approval(self):
        for _ in range(2):
            with self.assertRaisesRegex(ReviewError, "hash_mismatch"):
                self.review(expected_hash="0" * 64)
        self.assertEqual(self.runs.db.execute("SELECT state FROM proposals").fetchone()[0], "PENDING")
        self.assertEqual(self.runs.db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0], 1)
        with self.assertRaisesRegex(ReviewError, "request_id_conflict"):
            self.review()

    def test_expired_review_transitions_once_and_replay_remains_failure(self):
        self.now += timedelta(hours=24)
        for _ in range(2):
            with self.assertRaisesRegex(ReviewError, "proposal_expired"):
                self.review()
        self.assertEqual(self.runs.db.execute("SELECT state,version FROM proposals").fetchone(), ("EXPIRED", 2))

    def test_new_snapshot_makes_pending_review_stale(self):
        changed = copy.deepcopy(self.evidence.snapshot)
        changed["snapshot_version"] = 2
        changed["records"][0]["version"] = 2
        self.runs.register_snapshot(MemoryEvidence(snapshot=changed))
        with self.assertRaisesRegex(ReviewError, "snapshot_or_policy_stale"):
            self.review()
        self.assertEqual(self.runs.db.execute("SELECT state,version FROM proposals").fetchone(), ("STALE", 2))
        self.assertEqual(canonical(self.evidence.snapshot), self.original)

    def test_record_versions_and_payload_integrity_are_checked_individually(self):
        context = {"identity_id": self.payload["identity_id"], "identity_version": self.payload["identity_version"],
                   "user_id": self.payload["user_id"],
                   "sessions": {"login-002": {"session_id": "session-002", "version": 1}}}
        current = {"version": 1, "digest": self.evidence.snapshot_digest, "context": context}
        for mutate in (lambda c: c["context"].update(identity_version=2),
                       lambda c: c["context"]["sessions"]["login-002"].update(version=2)):
            changed = copy.deepcopy(current)
            mutate(changed)
            with self.assertRaisesRegex(ReviewError, "identity_or_session_stale"):
                validate_review(self.payload, self.hash, "PENDING", 1, changed, self.hash, 1, NOW)
        corrupt = {**self.payload, "target_session_id": "other"}
        with self.assertRaisesRegex(ReviewError, "payload_corrupt"):
            validate_review(corrupt, self.hash, "PENDING", 1, current, self.hash, 1, NOW)

    def test_rejection_has_no_execution_and_version_mismatch_is_refused(self):
        with self.assertRaisesRegex(ReviewError, "version_mismatch"):
            self.review(request="wrong-version", version=2)
        self.assertEqual(self.review(request="rejection", decision="reject")["state"], "REJECTED")
        self.assertEqual(canonical(self.evidence.snapshot), self.original)


class ToolAndWireComponents(unittest.TestCase):
    def test_pagination_cursor_binding_restore_and_two_page_cap(self):
        evidence = MemoryEvidence(1)
        row = next(r for r in evidence.snapshot["records"] if r["kind"] == "auth")
        evidence.snapshot["records"] = [r for r in evidence.snapshot["records"] if r["kind"] != "auth"]
        for i in range(101):
            clone = copy.deepcopy(row)
            clone["id"] = f"r{i:03}"
            evidence.snapshot["records"].append(clone)
        evidence.snapshot_digest = digest(evidence.snapshot)
        tools = EvidenceTools(evidence)
        first = tools.call("search_events", {"kind": "auth"})
        self.assertTrue(first["truncated"])
        self.assertEqual(len(first["records"]), 50)
        restored = EvidenceTools(evidence)
        restored.remember(first)
        with self.assertRaisesRegex(ContractError, "mismatched_cursor"):
            restored.call("search_events", {"kind": "resource", "cursor": first["next_cursor"]})
        second = restored.call("search_events", {"kind": "auth", "cursor": first["next_cursor"]})
        self.assertTrue(second["truncated"])
        self.assertIsNone(second["next_cursor"])
        self.assertFalse(restored.complete_event_read("auth"))
        with self.assertRaisesRegex(ContractError, "duplicate_query"):
            restored.call("search_events", {"kind": "auth", "cursor": first["next_cursor"]})
        with self.assertRaisesRegex(ContractError, "unissued"):
            restored.call("search_events", {"kind": "auth", "cursor": "invented"})

    def test_fifty_one_rows_complete_after_second_page(self):
        evidence = MemoryEvidence(1)
        row = next(r for r in evidence.snapshot["records"] if r["kind"] == "auth")
        evidence.snapshot["records"] = [{**copy.deepcopy(row), "id": f"r{i:03}"} for i in range(51)]
        evidence.snapshot_digest = digest(evidence.snapshot)
        tools = EvidenceTools(evidence)
        first = tools.call("search_events", {"kind": "auth"})
        tools.call("search_events", {"kind": "auth", "cursor": first["next_cursor"]})
        self.assertTrue(tools.complete_event_read("auth"))
        self.assertEqual(len(tools.seen), 51)

    def test_restored_observation_cannot_substitute_record_content(self):
        evidence = MemoryEvidence(1)
        tools = EvidenceTools(evidence)
        original = tools.call("get_identity_context", {})
        corrupt = copy.deepcopy(original)
        corrupt["records"][0]["data"]["user_id"] = "other-user"
        with self.assertRaisesRegex(ContractError, "observation_record_corrupt"):
            EvidenceTools(evidence).remember(corrupt)

    def test_window_and_exact_ip_filters_cannot_expand_scope(self):
        tools = EvidenceTools(MemoryEvidence(1))
        for args in ({"kind": "auth", "from": "2026-10-07T08:59:00Z"},
                     {"kind": "auth", "to": "2026-10-07T10:01:00Z"},
                     {"kind": "auth", "ip": "198.51.100.999"}):
            with self.subTest(args=args), self.assertRaises(ContractError):
                tools.call("search_events", args)
        self.assertEqual(tools.observations, [])

    def test_approved_travel_can_support_benign_with_complete_reads(self):
        source = json.loads((ROOT / "fixtures/development/case-003.json").read_text(encoding="utf-8"))
        tools = EvidenceTools(MemoryEvidence(snapshot=source))
        for name, args in [("get_identity_context", {}), ("search_events", {"kind": "auth"}),
                           ("get_telemetry_status", {}), ("get_device_context", {"device_id": source["alert"]["device_id"]}),
                           ("get_travel_context", {"ip": source["alert"]["ip"]}), ("search_events", {"kind": "resource"})]:
            tools.call(name, args)
        kinds = {"coverage": "COVERAGE_COMPLETE", "auth": "AUTH_SUCCESS",
                 "device": "DEVICE_MANAGED", "travel": "TRAVEL_APPROVED"}
        final = {"disposition": "BENIGN", "urgency": "LOW", "claims": [
            claim(kinds[r["kind"]], r) for r in tools.seen.values() if r["kind"] in kinds],
            "gaps": [], "hypotheses": ["APPROVED_TRAVEL"], "reason": "corroborated_benign_context", "proposal": None}
        self.assertEqual(validate_final(final, tools)["disposition"], "BENIGN")

    def test_wire_continuation_native_schemas_and_single_tool_response(self):
        conversation = [{"role": "system", "instruction": "data only"},
                        {"role": "assistant", "call": {"tool": "get_identity_context", "arguments": {}}},
                        {"role": "tool", "observation": {"tool": "get_identity_context", "records": []}},
                        {"role": "host_feedback", "reason": "unsupported_claim"}]
        request = json.loads(wire_request("model-test", conversation, CATALOG))
        self.assertFalse(request["stream"])
        self.assertEqual(request["messages"][1]["tool_calls"][0]["function"]["name"], "get_identity_context")
        self.assertEqual(request["messages"][2]["role"], "tool")
        self.assertEqual(request["messages"][2]["tool_name"], "get_identity_context")
        self.assertFalse(request["tools"][0]["function"]["parameters"]["additionalProperties"])
        turn, usage = wire_response(reply(prompt_eval_count=4, eval_count=2), CATALOG)
        self.assertEqual(json.loads(turn), {"tool": "get_identity_context", "arguments": {}})
        self.assertEqual(usage["eval_count"], 2)
        self.assertIsNone(usage["total_duration"])

    def test_wire_malformed_multiple_unknown_and_oversized_are_refused(self):
        examples = ["not-json", canonical({"done": False}), reply("delete_session"),
                    '{"done":true,"message":{"role":"assistant","tool_calls":[]}}', " " * 65537]
        multiple = json.loads(reply())
        multiple["message"]["tool_calls"] *= 2
        examples.append(canonical(multiple))
        for raw in examples:
            with self.subTest(raw=raw[:50]), self.assertRaises(ContractError):
                wire_response(raw, CATALOG)

    def test_injected_transport_retries_once_and_nonretry_status_fails(self):
        replies = [(500, b"{}"), (200, reply())]
        observed = []
        def transport(body, timeout):
            observed.append((body, timeout))
            return replies.pop(0)
        provider = OllamaProvider("test-double", transport=transport)
        with patch("security_triage.ollama.time.sleep", return_value=None):
            provider.next_turn([], CATALOG, {"seconds": 5})
        self.assertEqual(len(observed), 2)
        self.assertEqual(provider.last_usage["retries"], 1)
        self.assertEqual(provider.configuration["mode"], "protocol_double")
        denied = OllamaProvider("test", transport=lambda *_: (401, b"{}"))
        with self.assertRaisesRegex(ContractError, "status_401"):
            denied.next_turn([], CATALOG, {"seconds": 5})
        self.assertEqual(denied.last_usage["wire_requests"], 1)
        with self.assertRaisesRegex(ContractError, "cancel_requested"):
            denied.next_turn([], CATALOG, {"seconds": 5, "cancelled": lambda: True})
        with self.assertRaisesRegex(ContractError, "deadline_exhausted"):
            denied.next_turn([], CATALOG, {"seconds": 0})
        self.assertEqual(denied.last_usage["wire_requests"], 0)

    def test_baseline_fixed_next_read_and_no_travel_adaptation(self):
        provider = FixedBaseline()
        alert = MemoryEvidence(1).snapshot["alert"]
        conversation = [{"role": "system"}, {"role": "user", "alert": alert}]
        self.assertEqual(json.loads(provider.next_turn(conversation, CATALOG, {}))["tool"], "get_identity_context")
        observed = [{"tool": name, "arguments": args, "records": []} for name, args in [
            ("get_identity_context", {}), ("search_events", {"kind": "auth"}),
            ("get_telemetry_status", {}), ("get_device_context", {"device_id": alert["device_id"]}),
            ("get_network_context", {"ip": alert["ip"]})]]
        conversation += [{"role": "tool", "observation": o} for o in observed]
        self.assertEqual(json.loads(provider.next_turn(conversation, CATALOG, {})),
                         {"tool": "search_events", "arguments": {"kind": "resource"}})

    def test_development_inputs_are_twelve_valid_fictional_snapshots(self):
        paths = sorted((ROOT / "fixtures/development").glob("*.json"))
        self.assertEqual(len(paths), 12)
        for path in paths:
            validate_snapshot(json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
