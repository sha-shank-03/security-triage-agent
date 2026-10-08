"""Complete M1 acceptance: run only in the granted integration window."""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from evaluation.verify import VerificationError, verify
from security_triage.cli import demo
from security_triage.contracts import canonical
from security_triage.loop import investigate
from security_triage.providers import ScriptedInvestigator
from security_triage.store import EvidenceStore, RunStore, create_evidence

ROOT = Path(__file__).resolve().parents[1]


class TamperingProvider:
    name = "tampering_local_double"

    def __init__(self, mutate):
        self.delegate = ScriptedInvestigator()
        self.mutate = mutate

    def next_turn(self, conversation, schemas, remaining):
        turn = json.loads(self.delegate.next_turn(conversation, schemas, remaining))
        if turn["tool"] == "finish_investigation":
            self.mutate(turn["arguments"])
        return canonical(turn)


class SliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "work").mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="slice-", dir=ROOT / "work")
        cls.root = Path(cls.temporary.name)
        cls.original = cls.root / "original"
        cls.packet = demo(cls.original)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_three_dispositions_and_no_containment_mutation(self):
        result = verify(self.original)
        self.assertEqual(result["dispositions_correct"], 3)
        self.assertEqual(result["pending_proposals"], 1)
        self.assertEqual(result["containment_mutations"], 0)
        self.assertGreaterEqual(result["evidence_calls"], 9)
        self.assertGreater(result["typed_claims_supported"], 0)

    def test_provider_uses_new_observed_device_and_branch_order(self):
        cases = {c["case_id"]: c for c in self.packet["cases"]}
        benign = cases["demo-001"]["observations"]
        suspicious = cases["demo-002"]["observations"]
        self.assertEqual(benign[3]["tool"], "get_network_context")
        self.assertEqual(suspicious[3]["tool"], "get_device_context")
        self.assertEqual(suspicious[3]["arguments"], {"device_id": "device-002"})
        self.assertEqual(cases["demo-003"]["final"]["gaps"], ["coverage-auth-003"])
        self.assertEqual(len(cases["demo-003"]["observations"]), 3)

    def test_completed_demo_reuses_runs_without_duplicate_proposals(self):
        repeated = demo(self.original)
        self.assertEqual(repeated["cases"], self.packet["cases"])
        self.assertEqual(verify(self.original)["pending_proposals"], 1)

    def test_malformed_provider_output_is_guarded_and_raw_is_preserved(self):
        fixture = json.loads((ROOT / "fixtures" / "demo" / "case-002.json").read_text(encoding="utf-8"))
        path = self.root / "malformed"
        path.mkdir()
        create_evidence(path / "evidence.sqlite", [fixture])
        evidence = EvidenceStore(path / "evidence.sqlite", fixture["case_id"])
        runs = RunStore(path / "runs.sqlite")
        provider = TamperingProvider(lambda final: final["claims"][0].update(record_id="invented-record"))
        try:
            run_id = investigate(evidence, runs, provider)
            final = json.loads(runs.db.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()[0])
            raw = runs.db.execute("SELECT raw_json FROM attempts WHERE run_id=? AND accepted=0", (run_id,)).fetchall()
            self.assertEqual(final["disposition"], "INCONCLUSIVE")
            self.assertEqual(final["stop_reason"], "correction_budget_exhausted")
            self.assertEqual(len(raw), 3)
            self.assertTrue(all(json.loads(r[0])["arguments"]["disposition"] == "ESCALATE" for r in raw))
            self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 0)
        finally:
            evidence.close()
            runs.close()

    def test_forged_session_target_is_rejected(self):
        fixture = json.loads((ROOT / "fixtures" / "demo" / "case-002.json").read_text(encoding="utf-8"))
        path = self.root / "forged"
        path.mkdir()
        create_evidence(path / "evidence.sqlite", [fixture])
        evidence = EvidenceStore(path / "evidence.sqlite", fixture["case_id"])
        runs = RunStore(path / "runs.sqlite")
        provider = TamperingProvider(lambda final: final["proposal"].update(target_session_id="other-session"))
        try:
            investigate(evidence, runs, provider)
            self.assertEqual(runs.db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 0)
            reasons = [r[0] for r in runs.db.execute("SELECT reason FROM attempts WHERE accepted=0")]
            self.assertEqual(reasons, ["proposal_target_not_supported"] * 3)
        finally:
            evidence.close()
            runs.close()

    def test_independent_verifier_rejects_corrupt_disposition_claim_and_proposal(self):
        for field in ("disposition", "claim", "proposal"):
            with self.subTest(field=field):
                target = self.root / ("corrupt-" + field)
                shutil.copytree(self.original, target)
                db = sqlite3.connect(target / "runs.sqlite")
                try:
                    run_id = db.execute("SELECT run_id FROM runs WHERE case_id='demo-002'").fetchone()[0]
                    if field == "proposal":
                        raw = db.execute("SELECT payload_json FROM proposals WHERE run_id=?", (run_id,)).fetchone()[0]
                        payload = json.loads(raw)
                        payload["target_session_id"] = "other-session"
                        db.execute("UPDATE proposals SET payload_json=? WHERE run_id=?", (canonical(payload), run_id))
                    else:
                        final = json.loads(db.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()[0])
                        if field == "disposition":
                            final["disposition"] = "BENIGN"
                        else:
                            final["claims"][0]["value"] = not final["claims"][0]["value"]
                        db.execute("UPDATE dispositions SET final_json=? WHERE run_id=?", (canonical(final), run_id))
                    db.commit()
                finally:
                    db.close()
                with self.assertRaises(VerificationError):
                    verify(target)


if __name__ == "__main__":
    unittest.main()
