"""Deferred M3 integration: actual disk corruption and label-access denial."""

import copy
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evaluation.heldout_score import load_case
from evaluation.independent import canonical, validate_case
from evaluation.verify import VerificationError, _hash, _readonly
from security_triage.cli import run_snapshots
from security_triage.providers import ScriptedInvestigator

ROOT = Path(__file__).resolve().parents[1]


class M3Integration(unittest.TestCase):
    def setUp(self):
        (ROOT / "work").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m3-integration-", dir=ROOT / "work")
        self.root = Path(self.temporary.name)
        self.source = json.loads((ROOT / "fixtures/demo/case-002.json").read_text(encoding="utf-8"))

    def tearDown(self):
        self.temporary.cleanup()

    def verify_directory(self, directory):
        evidence, runs = _readonly(directory / "evidence.sqlite"), _readonly(directory / "runs.sqlite")
        try:
            return validate_case(load_case(evidence, runs, self.source, "scripted", 1))
        finally:
            evidence.close()
            runs.close()

    def test_actual_disk_mutations_cannot_rubber_stamp_outcomes(self):
        original = self.root / "original"
        run_snapshots([self.source], original, ScriptedInvestigator(), request_id="heldout-repeat-1")
        self.assertEqual(self.verify_directory(original)["final"]["disposition"], "ESCALATE")
        for mutation in ("verdict", "reference", "version", "target", "snapshot_version", "review_state", "source_index"):
            with self.subTest(mutation=mutation):
                directory = self.root / mutation
                shutil.copytree(original, directory)
                path = directory / ("evidence.sqlite" if mutation == "source_index" else "runs.sqlite")
                db = sqlite3.connect(path)
                try:
                    if mutation == "source_index":
                        db.execute("UPDATE records SET kind='resource' WHERE record_id='login-002'")
                    elif mutation == "review_state":
                        db.execute("UPDATE proposals SET state='APPROVED_SIMULATION',version=2")
                    elif mutation in ("target", "snapshot_version"):
                        raw = db.execute("SELECT payload_json FROM proposals").fetchone()[0]
                        payload = json.loads(raw)
                        payload["target_session_id" if mutation == "target" else "snapshot_version"] = (
                            "other-session" if mutation == "target" else 2)
                        hashed = _hash(payload)
                        db.execute("UPDATE proposals SET proposal_id=?,payload_hash=?,payload_json=?",
                                   (hashed[:24], hashed, canonical(payload)))
                    else:
                        final = json.loads(db.execute("SELECT final_json FROM dispositions").fetchone()[0])
                        if mutation == "verdict":
                            final["disposition"] = "BENIGN"
                        else:
                            final["claims"][0]["record_id" if mutation == "reference" else "record_version"] = (
                                "invented-record" if mutation == "reference" else 2)
                        db.execute("UPDATE dispositions SET final_json=?", (canonical(final),))
                        if mutation != "verdict":
                            raw = canonical({"tool": "finish_investigation", "arguments": {
                                k: v for k, v in final.items() if k not in ("execution_status", "stop_reason")}})
                            db.execute("UPDATE attempts SET raw_json=? WHERE reason='validated_finish'", (raw,))
                    db.commit()
                finally:
                    db.close()
                with self.assertRaises(VerificationError):
                    self.verify_directory(directory)

    def test_actor_reads_no_labels_and_sentinel_label_replacement_changes_no_trace(self):
        digests = []
        original_reader = Path.read_text
        sentinels = ["UNTRUSTED_LABEL_SENTINEL_BENIGN", "UNTRUSTED_LABEL_SENTINEL_ESCALATE"]
        for index, sentinel in enumerate(sentinels):
            reads, conversations = [], []
            def read_text(path, *args, **kwargs):
                if "evaluation" in path.parts and "labels" in path.parts:
                    reads.append(str(path))
                    return canonical({"world_truth": sentinel})
                return original_reader(path, *args, **kwargs)

            class Spy:
                name = ScriptedInvestigator.name
                configuration = ScriptedInvestigator.configuration
                def next_turn(self, conversation, catalog, budget):
                    conversations.append(canonical({"conversation": conversation, "catalog": catalog}))
                    return ScriptedInvestigator().next_turn(conversation, catalog, budget)

            directory = self.root / ("sentinel-" + str(index))
            with patch.object(Path, "read_text", read_text):
                run_snapshots([copy.deepcopy(self.source)], directory, Spy(), request_id="heldout-repeat-1")
            self.assertEqual(reads, [])
            self.assertFalse(any(sentinel in conversation for conversation in conversations))
            digests.append(self.verify_directory(directory)["semantic_digest"])
        self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
