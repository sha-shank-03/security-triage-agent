"""Pure small contract probes, not a split run. Sockets/processes are blocked."""

import ast
import copy
import json
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from evaluation.upgrade_dataset import FAMILIES, ROOT, load_inputs, semantic_digest, verify_dataset
from evaluation.upgrade_score import aggregate, domain_truth, score_bundle
from evaluation.upgrade_verify import validate_packet
from evaluation.verify import VerificationError
from security_triage.complete_playbook import PlaybookTransport, next_call
from security_triage.contracts import canonical, digest
from security_triage.gateway import GatewayConfig
from security_triage.store import validate_snapshot
from security_triage.tools import EvidenceTools
from security_triage.upgrade import bundle
from security_triage.upgrade_double import completion
from security_triage.upgrade_runtime import investigate
from security_triage.upgrade_state import UpgradeState


class MemoryEvidence:
    def __init__(self, source):
        validate_snapshot(source)
        self.snapshot, self.snapshot_digest = source, digest(source)
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE records(kind TEXT, value TEXT)")
        self.db.executemany("INSERT INTO records VALUES(?,?)", [(r["kind"], canonical(r)) for r in source["records"]])

    def records(self, kind):
        rows = [json.loads(r[0]) for r in self.db.execute("SELECT value FROM records WHERE kind=?", (kind,))]
        start, end = self.snapshot["window_start"], self.snapshot["cutoff"]
        return sorted([r for r in rows if r["event_time"] <= end and r["ingested_at"] <= end
                       and (kind not in ("auth", "resource") or r["event_time"] >= start)], key=lambda r: (r["event_time"], r["id"]))


def probe():
    source = json.loads((ROOT / "fixtures/demo/case-002.json").read_text())
    source["case_id"] = "pure-u2b-probe"
    return source


def label(source):
    truth, urgency, gaps = domain_truth(source)
    return {"case_id": source["case_id"], "world_truth": truth, "allowed_dispositions": [truth],
            "allowed_urgencies": [urgency], "required_gaps": gaps, "expected_proposal": None,
            "severity_stratum": source["alert"]["priority"], "family": "pure-probe", "label_exposure": "worker-exposed"}


def trace(source, transport=None, config=None):
    evidence = MemoryEvidence(source)
    state = UpgradeState(":memory:", clock=lambda: datetime(2026, 10, 12, 8, tzinfo=timezone.utc), monotonic=lambda: 0)
    try:
        before = evidence.db.execute("SELECT value FROM records ORDER BY value").fetchall()
        investigate(evidence, state, config or GatewayConfig(), transport or PlaybookTransport(monotonic=lambda: 0), code_sha256="a" * 64)
        after = evidence.db.execute("SELECT value FROM records ORDER BY value").fetchall()
        if before != after: raise AssertionError("evidence mutation")
        return bundle(state)
    finally:
        evidence.db.close(); state.close()


class EvaluationPure(unittest.TestCase):
    def setUp(self):
        blockers = [patch.object(socket, "socket", side_effect=AssertionError("pure probe opened socket")),
                    patch.object(socket, "create_connection", side_effect=AssertionError("pure probe opened socket")),
                    patch.object(subprocess, "Popen", side_effect=AssertionError("pure probe spawned process"))]
        for blocker in blockers: blocker.start(); self.addCleanup(blocker.stop)

    def test_static_authored_counts_exposure_hashes_and_disjoint_ids(self):
        result = verify_dataset()
        self.assertEqual(result["worker_exposed_tasks"], 24)
        ids = []
        for split in ("development", "capability"):
            manifest, sources = load_inputs(split)
            self.assertEqual(len(sources), 12)
            self.assertEqual({c["family"] for c in manifest["cases"]}, set(FAMILIES))
            ids.extend(source["case_id"] for _, source in sources)
            for item, source in sources:
                self.assertFalse({"label", "truth", "world_truth", "family"} & source.keys())
                self.assertEqual(item["semantic_sha256"], semantic_digest(source))
        self.assertEqual(len(set(ids)), 24)
        with self.assertRaises(VerificationError): load_inputs("acceptance")

    def test_interruption_persists_started_marker_without_executing_actor(self):
        from evaluation.upgrade_run import run
        source = probe()
        with tempfile.TemporaryDirectory() as directory, patch("evaluation.upgrade_run.load_inputs", return_value=({}, [({"sha256": "a" * 64}, source)])), \
                patch("evaluation.upgrade_run.run_baseline", side_effect=KeyboardInterrupt) as actor:
            out = Path(directory) / "run"
            with self.assertRaises(KeyboardInterrupt): run("development", ["complete-playbook-v2"], out)
            saved = json.loads((out / "manifest.json").read_text())
            self.assertEqual(saved["executions"][0]["status"], "STARTED")
            self.assertFalse(saved["complete"])
            actor.assert_called_once()

    def test_baseline_source_has_no_id_label_file_or_evaluator_branch(self):
        path = ROOT / "security_triage/complete_playbook.py"
        tree = ast.parse(path.read_text())
        self.assertFalse(any(isinstance(n, ast.Constant) and n.value in ("case_id", "world_truth", "label", "family") for n in ast.walk(tree)))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open" for n in ast.walk(tree)))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom): self.assertFalse((node.module or "").startswith("evaluation"))
        for name in ("upgrade_score.py", "upgrade_dataset.py"):
            tree = ast.parse((ROOT / "evaluation" / name).read_text())
            self.assertFalse(any(isinstance(n, ast.ImportFrom) and (n.module or "").startswith("security_triage") for n in ast.walk(tree)))

    def test_positive_misuse_outranks_missing_telemetry_in_memory_state(self):
        source = probe()
        coverage = next(r for r in source["records"] if r["kind"] == "coverage")
        coverage["data"].update(complete=False, gap="synthetic pure gap")
        packet = trace(source)
        scored = score_bundle(packet, source, label(source))
        self.assertEqual((scored["raw"], scored["guarded"], scored["state"]), ("ESCALATE", "ESCALATE", "COMPLETED"))
        self.assertTrue(scored["gaps_correct"])
        self.assertTrue(scored["task_success"])
        self.assertLessEqual(packet["run"]["attempts"], 12)

    def test_baseline_can_complete_benign_with_network_or_travel_corroboration(self):
        for travel in (False, True):
            source = probe()
            source["records"] = [r for r in source["records"] if not (r["kind"] == "auth" and r["data"]["outcome"] == "failure")]
            for record in source["records"]:
                if record["kind"] == "device": record["data"]["managed"] = True
                if record["kind"] == "resource": record["data"]["sensitive"] = False
                if record["kind"] == "network": record["data"]["approved"] = not travel
            if travel:
                record = copy.deepcopy(next(r for r in source["records"] if r["kind"] == "network"))
                record.update(id="pure-travel", kind="travel"); record["data"]["approved"] = True
                source["records"].append(record)
            result = score_bundle(trace(source), source, label(source))
            self.assertEqual((result["raw"], result["guarded"], result["state"]), ("BENIGN", "BENIGN", "COMPLETED"))
            self.assertTrue(result["task_success"])

    def test_baseline_finishes_event_pages_before_terminal_answer(self):
        source = probe(); tools = EvidenceTools(MemoryEvidence(source))
        self.addCleanup(tools.store.db.close)
        initial = {"alert": source["alert"], "window_start": source["window_start"], "cutoff": source["cutoff"]}
        observations = []
        for _ in range(11):
            tool, args = next_call(initial, observations)
            if tool == "finish_investigation": break
            observations.append(tools.call(tool, args))
        self.assertEqual(tool, "finish_investigation")
        self.assertTrue(all(tools.complete_event_read(s) for s in ("auth", "resource")))
        self.assertIn("get_travel_context", {o["tool"] for o in observations})

    def test_unseen_page_cursor_is_followed_before_decision(self):
        initial = {"alert": probe()["alert"], "window_start": probe()["window_start"], "cutoff": probe()["cutoff"]}
        rows = [{"tool": "get_identity_context", "records": [], "arguments": {}},
                {"tool": "search_events", "records": [], "arguments": {"kind": "auth"}, "next_cursor": "issued-pure-cursor"}]
        self.assertEqual(next_call(initial, rows), ("search_events", {"kind": "auth", "cursor": "issued-pure-cursor"}))

    def test_lower_attempt_budget_is_a_retained_handoff_not_fake_success(self):
        source = probe(); packet = trace(source, config=GatewayConfig(max_attempts=2))
        result = score_bundle(packet, source, label(source))
        self.assertEqual((result["state"], result["raw"], result["guarded"]), ("HANDOFF", "NO_FINAL", "INCONCLUSIVE"))
        self.assertFalse(result["task_success"]); self.assertEqual(result["attempts"], 2)

    def test_false_completion_raw_benign_is_preserved_and_guarded(self):
        class FalseFinish:
            def send(self, request, deadline, cancelled):
                seq = 1 + sum(m["role"] == "user" for m in request["messages"])
                final = {"disposition": "BENIGN", "urgency": "LOW", "claims": [], "gaps": [], "hypotheses": ["APPROVED_NETWORK"],
                         "reason": "corroborated_benign_context", "proposal": None}
                return 200, canonical(completion("finish_investigation", final, seq))
        source = probe(); packet = trace(source, transport=FalseFinish())
        result = score_bundle(packet, source, label(source))
        self.assertEqual((result["raw"], result["guarded"], result["state"]), ("BENIGN", "INCONCLUSIVE", "HANDOFF"))
        self.assertFalse(result["raw_correct"]); self.assertFalse(result["task_success"])

    def test_fake_completion_missing_evidence_and_corruption_are_rejected(self):
        source = probe(); packet = trace(source)
        mutations = [lambda p: p["run"].update(state="HANDOFF"),
                     lambda p: p["outcome"]["guarded"]["claims"][0].update(record_version=999),
                     lambda p: p["attempts"][0]["observation"]["records"][0]["data"].update(privileged=True),
                     lambda p: p["attempts"][1].update(observation=None),
                     lambda p: p["events"][1]["data"].update(actual_cost=100),
                     lambda p: p["run"]["source"]["alert"].update(ip="192.0.2.99")]
        for change in mutations:
            altered = copy.deepcopy(packet); change(altered)
            with self.assertRaises(VerificationError): score_bundle(altered, source, label(source))

    def test_metrics_retain_ties_failures_handoffs_and_unknown_cost(self):
        source = probe(); source["records"] = [r for r in source["records"] if r["kind"] != "auth"]
        result = score_bundle(trace(source), source, label(source))
        handoff = score_bundle(trace(source, config=GatewayConfig(max_attempts=2)), source, label(source))
        a = {**result, "provider": "complete-playbook-v2", "execution_wall_seconds": .2}
        b = {**handoff, "provider": "gateway-double", "execution_wall_seconds": .4}
        failed = {**a, "case_id": "pure-unexecuted", "state": "FAILED", "verified": False, "raw": "NO_RESULT", "guarded": "NO_RESULT",
                  "raw_correct": False, "guarded_correct": False, "task_success": False, "elapsed_seconds": None, "execution_wall_seconds": .1,
                  "raw_claims": 0, "raw_supported_claims": 0, "guarded_claims": 0}
        pending = {**failed, "provider": "gateway-double", "state": "PENDING", "execution_wall_seconds": None}
        report = aggregate([a, b, failed, pending], ["complete-playbook-v2", "gateway-double"])
        self.assertEqual(report["paired"]["counts"], {"tie": 2})
        self.assertEqual(report["providers"]["gateway-double"]["states"], {"HANDOFF": 1, "PENDING": 1})
        self.assertEqual(report["providers"]["complete-playbook-v2"]["states"], {"COMPLETED": 1, "FAILED": 1})
        self.assertIsNone(report["providers"]["complete-playbook-v2"]["actual_cost_per_success_minor_units"])
        self.assertEqual(report["providers"]["gateway-double"]["execution_wall_latency_seconds"]["N"], 1)


if __name__ == "__main__": unittest.main()
