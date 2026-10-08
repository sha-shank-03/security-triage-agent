"""Lightweight contract/scope checks; does not run the demo or acting loop."""

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from security_triage.contracts import Budget, ContractError, decode_turn, strict_json
from security_triage.policy import adverse_sequence, claim, validate_final
from security_triage.store import EvidenceStore, create_evidence, validate_snapshot
from security_triage.tools import EvidenceTools

ROOT = Path(__file__).resolve().parents[1]


def source(number=1):
    return json.loads((ROOT / "fixtures" / "demo" / f"case-{number:03}.json").read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_duplicate_keys_and_nan_rejected(self):
        for text in ('{"tool":"a","tool":"b","arguments":{}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(text=text), self.assertRaises(ContractError):
                strict_json(text)

    def test_turn_requires_exact_envelope(self):
        for text in ('[]', '{"tool":"read","arguments":[]}',
                     '{"tool":"read","arguments":{},"approve":true}', 'not JSON'):
            with self.subTest(text=text), self.assertRaises(ContractError):
                decode_turn(text)

    def test_budget_cannot_expand_host_limits(self):
        for values in ({"max_turns": 13}, {"max_turns": True}, {"max_corrections": 3}, {"deadline_seconds": 61}):
            with self.subTest(values=values), self.assertRaises(ContractError):
                Budget(**values)

    def test_input_subject_and_versions_are_validated(self):
        original = source()
        for mutate in (lambda s: s["records"][0]["data"].update(user_id="other-user"),
                       lambda s: s.update(snapshot_version=True),
                       lambda s: s["records"].append(copy.deepcopy(s["records"][0]))):
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.assertRaises(ContractError):
                validate_snapshot(changed)

    def test_duplicate_denial_references_do_not_inflate_sequence(self):
        records = source(2)["records"]
        denial = next(r for r in records if r["id"] == "deny-a-002")
        success = next(r for r in records if r["id"] == "login-002")
        self.assertEqual(len(adverse_sequence([denial, denial], success)), 1)


class ScopedToolTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="unit-", dir=ROOT / "work")
        self.path = Path(self.temporary.name) / "evidence.sqlite"
        create_evidence(self.path, [source()])
        self.store = EvidenceStore(self.path, "demo-001")
        self.tools = EvidenceTools(self.store)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def test_real_sqlite_read_and_write_denial(self):
        observation = self.tools.call("search_events", {"kind": "auth"})
        self.assertEqual([r["id"] for r in observation["records"]], ["login-001"])
        with self.assertRaises(sqlite3.OperationalError):
            self.store.db.execute("DELETE FROM records")

    def test_unknown_tool_cross_case_and_unobserved_session_rejected(self):
        for name, args in (("execute_sql", {"sql": "DELETE FROM records"}),
                           ("get_device_context", {"device_id": "device-002"}),
                           ("search_events", {"kind": "resource", "session_id": "session-001"}),
                           ("get_identity_context", {"case_id": "demo-002"})):
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.tools.call(name, args)
        self.assertEqual(self.tools.observations, [])

    def test_unseen_claim_cannot_finalize(self):
        final = {"disposition": "INCONCLUSIVE", "urgency": "MEDIUM", "claims": [
            claim("AUTH_SUCCESS", next(r for r in source()["records"] if r["kind"] == "auth"))],
            "gaps": [], "hypotheses": ["MISSING_TELEMETRY"], "reason": "insufficient_evidence", "proposal": None}
        with self.assertRaisesRegex(ContractError, "unseen_or_stale_reference"):
            validate_final(final, self.tools)

    def test_empty_resource_result_does_not_claim_coverage(self):
        self.tools.call("search_events", {"kind": "auth"})
        empty = self.tools.call("search_events", {"kind": "resource"})
        self.assertEqual(empty["status"], "empty")
        self.assertFalse(any(r["kind"] == "coverage" for r in self.tools.seen.values()))


if __name__ == "__main__":
    unittest.main()
