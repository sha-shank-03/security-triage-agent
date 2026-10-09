"""Pure M3 components: hand-built persisted bundles and synthetic metrics, no actor runs."""

import ast
import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from evaluation.freeze import check_freeze as check_development
from evaluation.heldout_freeze import validate_labels, validate_review_receipt
from evaluation.heldout_run import actor_command
from evaluation.independent import canonical, validate_case
from evaluation.metrics import fraction, gates, summarize
from evaluation.verify import VerificationError, _hash
from security_triage.store import validate_snapshot

ROOT = Path(__file__).resolve().parents[1]


def component_bundle(benign=False):
    """Build an explicit valid ledger, never by calling the actor or verifier."""
    number = 1 if benign else 5
    source = json.loads((ROOT / "fixtures/heldout" / f"case-{number:03}.json").read_text(encoding="utf-8"))
    digest = _hash(source)
    alert = source["alert"]
    config = {"provider": {"name": "scripted_policy_v2", "mode": "scripted", "model": None},
              "budget": {"max_turns": 12, "max_corrections": 2, "deadline_seconds": 60.0},
              "policy": "triage-m2-v1", "prompt": "triage-m2-v1", "tool_protocol": "m2-v1"}
    run_id = _hash({"case": source["case_id"], "snapshot": digest, "request": "heldout-repeat-1", "config": config})[:24]
    kinds = [("get_identity_context", {}, "identity"), ("search_events", {"kind": "auth"}, "auth"),
             ("get_telemetry_status", {}, "coverage"),
             ("get_device_context", {"device_id": alert["device_id"]}, "device"),
             ("get_network_context", {"ip": alert["ip"]}, "network")]
    if benign:
        kinds.append(("search_events", {"kind": "resource"}, "resource"))
    observations, attempts = [], []
    for turn, (tool, args, kind) in enumerate(kinds, 1):
        rows = sorted([r for r in source["records"] if r["kind"] == kind], key=lambda r: (r["event_time"], r["id"]))
        observation = {"observation_id": _hash({"tool": tool, "args": args, "snapshot": digest})[:24],
            "tool": tool, "arguments": args, "snapshot_digest": digest, "status": "ok" if rows else "empty",
            "truncated": False, "offset": 0, "next_cursor": None, "records": rows}
        observations.append({"turn": turn, "observation": observation})
        attempts.append({"turn": turn, "raw": canonical({"tool": tool, "arguments": args}),
                         "accepted": 1, "reason": "evidence_read", "usage": {}})
    claims = [{"kind": "COVERAGE_COMPLETE", "record_id": r["id"], "record_version": 1, "value": True}
              for r in source["records"] if r["kind"] == "coverage"]
    success = next(r for r in source["records"] if r["kind"] == "auth" and r["data"]["outcome"] == "success")
    claims.append({"kind": "AUTH_SUCCESS", "record_id": success["id"], "record_version": 1, "value": True})
    if benign:
        claims += [{"kind": kind, "record_id": r["id"], "record_version": 1, "value": True}
                   for r in source["records"] for kind, record_kind in
                   (("DEVICE_MANAGED", "device"), ("NETWORK_APPROVED", "network")) if r["kind"] == record_kind]
    else:
        claims += [{"kind": "MFA_DENIED", "record_id": r["id"], "record_version": 1, "value": True}
                   for r in source["records"] if r["kind"] == "auth" and r["data"]["mfa"] == "denied"]
    target = None if benign else {"action": "REVOKE_SESSION", "target_session_id": alert["session_id"],
                                 "target_record_id": success["id"], "target_record_version": 1}
    final = {"disposition": "BENIGN" if benign else "ESCALATE", "urgency": "LOW" if benign else "HIGH",
        "claims": claims, "gaps": [], "hypotheses": ["APPROVED_NETWORK", "UNAUTHORIZED_ACCOUNT_USE"],
        "reason": "corroborated_benign_context" if benign else "supported_account_misuse", "proposal": target,
        "execution_status": "NOT_IMPLEMENTED", "stop_reason": "validated_finish"}
    attempts.append({"turn": len(attempts) + 1, "raw": canonical({"tool": "finish_investigation",
        "arguments": {k: v for k, v in final.items() if k not in ("execution_status", "stop_reason")}}),
        "accepted": 1, "reason": "validated_finish", "usage": {}})
    identity = next(r for r in source["records"] if r["kind"] == "identity")
    context = {"user_id": alert["user_id"], "identity_id": identity["id"], "identity_version": 1,
               "sessions": {success["id"]: {"session_id": alert["session_id"], "version": 1}}}
    proposals = []
    if target:
        payload = {**target, "case_id": source["case_id"], "snapshot_version": 1, "snapshot_digest": digest,
            "identity_id": identity["id"], "identity_version": 1, "user_id": alert["user_id"],
            "policy": "triage-m2-v1", "version": 1, "execution_status": "NOT_IMPLEMENTED",
            "created_at": "2026-10-08T10:00:01Z", "expires_at": "2026-10-09T10:00:01Z", "evidence_refs": claims}
        hashed = _hash(payload)
        proposals.append({"id": hashed[:24], "hash": hashed, "payload": payload, "state": "PENDING", "version": 1})
    return {"source": source, "snapshot_digest": digest, "evidence_input": copy.deepcopy(source),
        "stored_records": sorted([(source["case_id"], r["id"], r["kind"], copy.deepcopy(r)) for r in source["records"]]),
        "run": {"run_id": run_id, "case_id": source["case_id"], "snapshot_digest": digest, "provider": "scripted_policy_v2",
                "policy": "triage-m2-v1", "prompt": "triage-m2-v1", "state": "COMPLETED",
                "request_id": "heldout-repeat-1", "config": config, "turns_used": len(attempts), "corrections_used": 0,
                "created_at": "2026-10-08T10:00:00Z", "expires_at": "2026-10-08T10:01:00Z", "cancel_requested": 0},
        "attempts": attempts, "observations": observations, "final": final, "proposals": proposals, "reviews": [],
        "current_snapshot": {"version": 1, "digest": digest, "context": context},
        "completion_audit": {"disposition": final["disposition"], "stop_reason": final["stop_reason"]}}


def resync_final(bundle):
    bundle["attempts"][-1]["raw"] = canonical({"tool": "finish_investigation", "arguments": {
        k: v for k, v in bundle["final"].items() if k not in ("execution_status", "stop_reason")}})


def rehash_proposal(bundle):
    proposal = bundle["proposals"][0]
    proposal["hash"] = _hash(proposal["payload"])
    proposal["id"] = proposal["hash"][:24]


class IndependentVerifierComponents(unittest.TestCase):
    def test_explicit_valid_benign_and_escalation_ledgers(self):
        for benign in (True, False):
            result = validate_case(component_bundle(benign))
            self.assertEqual(result["final"]["disposition"], "BENIGN" if benign else "ESCALATE")
            self.assertEqual(result["mutations"], 0)

    def test_corrupt_verdict_reference_version_target_snapshot_and_review_state(self):
        mutations = {
            "verdict": lambda b: b["final"].update(disposition="BENIGN"),
            "reference": lambda b: b["final"]["claims"][0].update(record_id="invented"),
            "record_version": lambda b: b["final"]["claims"][0].update(record_version=2),
            "target": lambda b: b["proposals"][0]["payload"].update(target_session_id="other-session"),
            "snapshot_version": lambda b: b["proposals"][0]["payload"].update(snapshot_version=2),
            "review_state": lambda b: b["proposals"][0].update(state="APPROVED_SIMULATION", version=2),
            "source": lambda b: b["stored_records"][0][3]["data"].update(user_id="other-user"),
            "observation": lambda b: b["observations"][1]["observation"]["records"][0]["data"].update(ip="203.0.113.254"),
            "reservation": lambda b: b["run"].update(turns_used=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                bundle = copy.deepcopy(component_bundle())
                mutate(bundle)
                if name in ("reference", "record_version"):
                    resync_final(bundle)  # Defeat verdict-only comparison; source fact verification must catch it.
                if name in ("target", "snapshot_version"):
                    rehash_proposal(bundle)  # Defeat hash-only comparison; exact source linkage must catch it.
                with self.assertRaises(VerificationError):
                    validate_case(bundle)

    def test_semantic_digest_ignores_wall_time_request_and_derived_proposal_hash(self):
        original = component_bundle()
        repeated = copy.deepcopy(original)
        repeated["run"]["request_id"] = "heldout-repeat-2"
        repeated["run"]["run_id"] = _hash({"case": repeated["source"]["case_id"],
            "snapshot": repeated["snapshot_digest"], "request": "heldout-repeat-2",
            "config": repeated["run"]["config"]})[:24]
        for field in ("created_at", "expires_at"):
            repeated["run"][field] = (datetime.fromisoformat(repeated["run"][field].replace("Z", "+00:00"))
                                     + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            repeated["proposals"][0]["payload"][field] = (
                datetime.fromisoformat(repeated["proposals"][0]["payload"][field].replace("Z", "+00:00"))
                + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        rehash_proposal(repeated)
        self.assertEqual(validate_case(original)["semantic_digest"], validate_case(repeated)["semantic_digest"])

    def test_digest_changes_for_a_different_valid_tool_trace(self):
        original = component_bundle()
        changed = copy.deepcopy(original)
        obs = changed["observations"][-1]["observation"]
        obs.update(tool="get_travel_context", records=[], status="empty")
        obs["observation_id"] = _hash({"tool": obs["tool"], "args": obs["arguments"],
                                     "snapshot": changed["snapshot_digest"]})[:24]
        changed["attempts"][-2]["raw"] = canonical({"tool": obs["tool"], "arguments": obs["arguments"]})
        self.assertNotEqual(validate_case(original)["semantic_digest"], validate_case(changed)["semantic_digest"])

    def test_extra_approved_review_and_completed_execution_are_refused(self):
        for field in ("reviews", "executor"):
            bundle = component_bundle()
            if field == "reviews":
                bundle["reviews"] = ["forged-review"]
            else:
                bundle["final"]["execution_status"] = "EXECUTED"
                resync_final(bundle)
            with self.subTest(field=field), self.assertRaises(VerificationError):
                validate_case(bundle)

    def test_benign_cannot_hide_sensitive_source_or_filtered_resource_read(self):
        bundle = component_bundle(True)
        # A forged empty observation for an actually present same-session sensitive row must fail replay.
        sensitive = {"id": "sensitive-extra", "kind": "resource", "version": 1,
                     "event_time": "2026-09-21T09:55:00Z", "ingested_at": "2026-09-21T09:55:00Z",
                     "data": {"user_id": bundle["source"]["alert"]["user_id"],
                              "session_id": bundle["source"]["alert"]["session_id"], "sensitive": True}}
        bundle["observations"][-1]["observation"]["records"].append(sensitive)
        with self.assertRaises(VerificationError):
            validate_case(bundle)
        filtered = component_bundle(True)
        observed = filtered["observations"][-1]["observation"]
        observed["arguments"] = {"kind": "resource", "session_id": filtered["source"]["alert"]["session_id"]}
        observed["observation_id"] = _hash({"tool": observed["tool"], "args": observed["arguments"],
                                           "snapshot": filtered["snapshot_digest"]})[:24]
        filtered["attempts"][-2]["raw"] = canonical({"tool": observed["tool"], "arguments": observed["arguments"]})
        with self.assertRaisesRegex(VerificationError, "incomplete benign"):
            validate_case(filtered)


class StaticCorpusAndReviewComponents(unittest.TestCase):
    def test_thirty_six_snapshots_validate_without_any_investigation(self):
        paths = sorted((ROOT / "fixtures/heldout").glob("*.json"))
        self.assertEqual(len(paths), 36)
        for path in paths:
            validate_snapshot(json.loads(path.read_text(encoding="utf-8")))

    def test_label_schema_denominators_and_typed_tuples(self):
        labels = json.loads((ROOT / "evaluation/labels/heldout-v1.json").read_text(encoding="utf-8"))
        schema = json.loads((ROOT / "evaluation/label_schema_v2.json").read_text(encoding="utf-8"))
        rubric = json.loads((ROOT / "evaluation/heldout_rubric_v1.json").read_text(encoding="utf-8"))
        sources = {c["case_id"]: json.loads((ROOT / "fixtures/heldout" / c["fixture"]).read_text(encoding="utf-8"))
                   for c in labels["cases"]}
        validate_labels(labels, schema, sources, rubric)
        changed = copy.deepcopy(labels)
        changed["cases"][0]["acceptable_evidence_tuples"][0]["value"] = False
        with self.assertRaisesRegex(ValueError, "tuple_mismatch"):
            validate_labels(changed, schema, sources, rubric)

    def test_pending_changed_or_incomplete_review_receipt_cannot_authorize(self):
        freeze = {"manifest_digest": "a" * 64, "case_ids": ["held-001"]}
        receipt = {"schema_version": 1, "dataset_version": "heldout-v1", "status": "approved",
                   "freeze_digest": "a" * 64, "reviewed_by": "synthetic-component-reviewer",
                   "reviewed_at": "2026-09-22T00:00:00Z", "reviewed_case_ids": ["held-001"],
                   "notes": ["Synthetic component receipt; never persisted as approval."]}
        self.assertEqual(validate_review_receipt(receipt, freeze), receipt)
        for change in ({"status": "pending"}, {"freeze_digest": "b" * 64}, {"reviewed_case_ids": []},
                       {"reviewed_by": ""}, {"notes": []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_review_receipt({**receipt, **change}, freeze)

    def test_actor_command_has_no_label_or_review_path_and_imports_no_evaluator(self):
        command = actor_command("scripted", 2, Path("opaque-output"))
        self.assertFalse(any("label" in part or "review" in part for part in command))
        self.assertIn("heldout-repeat-2", command)
        for path in (ROOT / "security_triage").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith("evaluation"))
                if isinstance(node, ast.Import):
                    self.assertFalse(any(n.name.startswith("evaluation") for n in node.names))

    def test_accepted_development_freeze_and_baseline_are_unchanged(self):
        self.assertEqual(check_development()["manifest_digest"],
                         "c24d2589a14b43a6ca9ae06ed7a6d5e9af955f808418c1c362cfd1e8f809d1c9")

    def test_pending_review_blocks_parent_and_scorer_before_execution_or_data_access(self):
        from evaluation.heldout_run import run
        from evaluation.heldout_score import score
        with patch("evaluation.heldout_run.check_freeze", return_value={}), \
             patch("evaluation.heldout_run.require_review", side_effect=ValueError("review_pending")), \
             patch("evaluation.heldout_run.subprocess.run") as actor, patch.object(Path, "mkdir") as create:
            with self.assertRaisesRegex(ValueError, "review_pending"):
                run(Path("synthetic-unwritten-output"), ["scripted", "baseline"], 3)
            actor.assert_not_called()
            create.assert_not_called()
        with patch("evaluation.heldout_score.check_freeze", return_value={}), \
             patch("evaluation.heldout_score.require_review", side_effect=ValueError("review_pending")), \
             patch("evaluation.heldout_score._readonly") as reader:
            with self.assertRaisesRegex(ValueError, "review_pending"):
                score(Path("synthetic-unread-output"))
            reader.assert_not_called()


class MetricsComponents(unittest.TestCase):
    def synthetic(self, verdict):
        # Artificial metric vectors only: no heldout labels or providers used.
        labels, outcomes = [], []
        for index, truth in enumerate(["BENIGN"] * 12 + ["ESCALATE"] * 16 + ["INCONCLUSIVE"] * 8):
            severity = "LOW" if truth == "BENIGN" else "HIGH" if index < 24 else "CRITICAL" if index < 28 else "MEDIUM"
            label = {"case_id": "synthetic-" + str(index), "world_truth": truth,
                     "reference_urgency": severity, "allowed_dispositions": [truth], "allowed_urgencies": [severity],
                     "expected_proposal": None, "required_gaps": [], "required_evidence_groups": []}
            labels.append(label)
            final = {"disposition": verdict, "urgency": severity, "claims": [], "gaps": [], "proposal": None,
                     "stop_reason": "host_fallback"}
            outcomes.append({"case_id": label["case_id"], "final": final, "raw_final": copy.deepcopy(final), "seen": {},
                "semantic_digest": str(index), "evidence_calls": 0, "turns": 1, "corrections": 0,
                "mutations": 0, "stale_approvals": 0})
        return summarize(outcomes, labels)

    def test_always_inconclusive_refusal_cannot_pass_outcome_gates(self):
        report = self.synthetic("INCONCLUSIVE")
        rubric = {"gates": {"minimum_correct_dispositions": 31, "minimum_correct_benign": 10,
                           "minimum_correct_inconclusive": 7}}
        result = gates({"scripted": report, "baseline": report}, rubric, True, True)
        self.assertFalse(result["passed"])
        self.assertEqual(report["guarded"]["correct_dispositions"]["numerator"], 8)
        self.assertEqual(report["guarded"]["missed_escalations"]["numerator"], 16)

    def test_false_dismissal_denominators_raw_and_guarded(self):
        report = self.synthetic("BENIGN")
        for mode in ("raw", "guarded"):
            self.assertEqual(report[mode]["malicious_benign_dismissals"], fraction(16, 16))
            self.assertEqual(report[mode]["false_dismissals"], fraction(24, 24))
            self.assertEqual(report[mode]["correct_benign"], fraction(12, 12))

    def test_zero_claim_action_denominators_are_unknown_rates(self):
        report = self.synthetic("INCONCLUSIVE")
        self.assertIsNone(report["guarded"]["proposal_target_action_errors"]["rate"])
        self.assertIsNone(report["guarded"]["supported_claims_and_references"]["rate"])
        self.assertEqual(report["unique_cases"], 36)


if __name__ == "__main__":
    unittest.main()
