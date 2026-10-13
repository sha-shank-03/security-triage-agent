"""Publication integrity probes; no actor/corpus execution or network/processes."""

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evaluation.upgrade_dataset import ROOT
from evaluation.upgrade_public import PINS, SUMMARY, build_summary, fingerprints, read_json, summarize, validate_summary
from evaluation.verify import VerificationError, _hash


class PublicReportPure(unittest.TestCase):
    def setUp(self):
        self.blocks = [patch(n, side_effect=AssertionError("pure probe forbids IO dispatch"))
                       for n in ("socket.socket", "socket.create_connection", "subprocess.Popen")]
        for block in self.blocks: block.start(); self.addCleanup(block.stop)
        self.pins = read_json(ROOT / PINS)
        self.summary = read_json(ROOT / SUMMARY)

    def reject(self, summary):
        with self.assertRaises((VerificationError, ValueError, KeyError, TypeError)):
            validate_summary(summary, self.pins)

    def test_first_summary_exact_fingerprints_and_all_five_misses(self):
        self.assertTrue(validate_summary(self.summary, self.pins)["passed"])
        cap = self.summary["splits"]["capability"]
        self.assertEqual(cap["providers"]["gateway-double"]["completed"], 12)
        self.assertEqual(cap["providers"]["gateway-double"]["task_success"], 7)
        self.assertEqual(len(cap["providers"]["gateway-double"]["domain_failures"]), 5)
        self.assertEqual(cap["paired"]["guarded_disposition"]["counts"],
                         {"complete-playbook-v2": 5, "gateway-double": 0, "tie": 7})

    def test_fake_completion_cannot_replace_domain_success(self):
        changed = copy.deepcopy(self.summary)
        changed["splits"]["capability"]["providers"]["gateway-double"]["task_success"] = 12
        self.reject(changed)
        row = next(copy.deepcopy(r) for r in self.summary["splits"]["capability"]["cases"] if not r["task_success"])
        row["task_success"] = True
        with self.assertRaises(VerificationError): summarize([row], [row["provider"]])

    def test_missing_slots_raw_erasure_and_denominator_changes_reject(self):
        for edit in (lambda s: s["splits"]["capability"]["cases"].pop(),
                     lambda s: s["splits"]["capability"]["cases"][0].pop("raw"),
                     lambda s: s.update(split_executions=35)):
            changed = copy.deepcopy(self.summary); edit(changed); self.reject(changed)

    def test_fabricated_cost_and_latency_are_rejected(self):
        for key, value in (("actual_cost_minor_units", 0), ("execution_wall_seconds", -1),
                           ("host_elapsed_seconds", float("nan"))):
            row = copy.deepcopy(self.summary["splits"]["capability"]["cases"][0]); row[key] = value
            with self.assertRaises(VerificationError): summarize([row], [row["provider"]])
        changed = copy.deepcopy(self.summary)
        changed["splits"]["capability"]["providers"]["gateway-double"]["actual_total_cost_minor_units"] = 0
        self.reject(changed)

    def test_urgency_gaps_and_full_task_pairing_are_distinct(self):
        cap = self.summary["splits"]["capability"]
        rows = copy.deepcopy(cap["cases"])
        # Tiny derived-metric probe, not a case rerun: class tie, urgency error.
        pair = [r for r in rows if r["case_id"] == rows[0]["case_id"]]
        for row in pair:
            row.update(raw_correct=True, raw_full_outcome_correct=True, guarded_correct=True, task_success=True,
                       guarded_full_outcome_correct=True)
        pair[1].update(guarded_urgency_correct=False, guarded_full_outcome_correct=False, task_success=False)
        result = summarize(pair, cap["paired"]["providers"])
        self.assertEqual(result["paired"]["guarded_disposition"]["counts"]["tie"], 1)
        self.assertEqual(result["paired"]["full_task"]["counts"]["complete-playbook-v2"], 1)

    def test_pending_failed_handoff_and_interrupted_slots_stay_in_denominators(self):
        template = self.summary["splits"]["development"]["cases"][0]
        rows = []
        for number, state in enumerate(("PENDING", "FAILED", "HANDOFF", "INTERRUPTED_UNKNOWN", "CANCELLED")):
            row = copy.deepcopy(template)
            row.update(case_id="probe-" + str(number), state=state, dispatch_status="PENDING" if number == 0 else state,
                       verified=False, task_success=False, execution_wall_seconds=None if number == 0 else float(number),
                       host_elapsed_seconds=None)
            rows.append(row)
        p = summarize(rows, [template["provider"]])["providers"][template["provider"]]
        self.assertEqual((p["intended"], p["dispatched"], p["completed"], p["task_success"]), (5, 4, 0, 0))
        self.assertEqual((p["execution_wall_latency_seconds"]["N"], p["execution_wall_latency_seconds"]["assigned_N"]), (4, 5))
        self.assertEqual(p["host_elapsed_latency_seconds"]["N"], 0)
        self.assertIsNone(p["actual_cost_per_success_minor_units"])

    def test_changed_source_or_evaluation_fingerprint_rejected(self):
        for key in ("actor_code_sha256", "eval_manifest_sha256", "source_manifest_sha256"):
            changed = copy.deepcopy(self.pins); changed[key] = "0" * 64
            with self.assertRaises(VerificationError): fingerprints(changed)

    def test_raw_report_corruption_missing_observation_and_duplicate_json_rejected(self):
        # Byte-bound first artifact rejects altered/missing observations before projection.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.json"
            path.write_text('{"observations":[{"kind":"auth"}]}', encoding="utf-8")
            expected = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
            self.assertEqual(len(read_json(path, expected)["observations"]), 1)
            path.write_text('{"observations":[]}', encoding="utf-8")
            with self.assertRaises(VerificationError): read_json(path, expected)
            path.write_text('{"cost":null,"cost":0}', encoding="utf-8")
            with self.assertRaises(VerificationError): read_json(path)

    def test_public_extra_private_fields_and_paths_rejected(self):
        for key, value in (("trace", []), ("sqlite", "state.sqlite"), ("private_path", "C:/Users/example/private")):
            changed = copy.deepcopy(self.summary); changed[key] = value; self.reject(changed)
        text = json.dumps(self.summary) + json.dumps(self.pins)
        for forbidden in ("C:/", "C:\\\\", "/Users/", "coordination/", "state.sqlite", "evidence.sqlite", '"records"', '"events"', '"claims"'):
            self.assertNotIn(forbidden, text)

    def test_exporter_has_no_actor_sql_or_dispatch_import_and_snapshot_not_current_run(self):
        tree = ast.parse((ROOT / "evaluation/upgrade_public.py").read_text())
        modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        modules += [v.name for n in ast.walk(tree) if isinstance(n, ast.Import) for v in n.names]
        self.assertFalse(any(m.startswith(("security_triage", "sqlite3", "subprocess", "socket", "urllib")) for m in modules))
        self.assertEqual(self.summary["provenance"]["eval_manifest_sha256"], self.pins["eval_manifest_sha256"])
        self.assertFalse(validate_summary(self.summary, self.pins)["private_state_reverified"])


if __name__ == "__main__": unittest.main()
