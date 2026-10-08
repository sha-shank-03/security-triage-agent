"""Exact-content local review. This module contains no containment executor."""

import json
from datetime import datetime

from .contracts import ContractError, POLICY_VERSION, canonical, digest, identifier, positive_integer
from .workflow import iso


class ReviewError(ContractError):
    def __init__(self, reason, transition=None):
        super().__init__(reason)
        self.transition = transition


def validate_review(payload, stored_hash, state, version, current, expected_hash, expected_version, now):
    positive_integer(expected_version)
    if not isinstance(expected_hash, str) or expected_hash != stored_hash:
        raise ReviewError("review_hash_mismatch")
    if digest(payload) != stored_hash:
        raise ReviewError("proposal_payload_corrupt")
    if expected_version != version:
        raise ReviewError("review_version_mismatch")
    if state != "PENDING":
        raise ReviewError("proposal_not_pending")
    if now.tzinfo is None:
        raise ReviewError("review_clock_not_aware")
    created = datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    if created.tzinfo is None or expiry.tzinfo is None or now < created:
        raise ReviewError("proposal_not_yet_valid")
    if now >= expiry:
        raise ReviewError("proposal_expired", "EXPIRED")
    if (not current or current["version"] != payload["snapshot_version"]
            or current["digest"] != payload["snapshot_digest"] or payload["policy"] != POLICY_VERSION):
        raise ReviewError("proposal_snapshot_or_policy_stale", "STALE")
    context = current["context"]
    if (context["identity_id"] != payload["identity_id"] or context["identity_version"] != payload["identity_version"]
            or context["user_id"] != payload["user_id"]
            or context["sessions"].get(payload["target_record_id"]) != {
                "session_id": payload["target_session_id"], "version": payload["target_record_version"]}):
        raise ReviewError("proposal_identity_or_session_stale", "STALE")
    if payload["action"] != "REVOKE_SESSION" or payload["execution_status"] != "NOT_IMPLEMENTED":
        raise ReviewError("unsupported_review_action")


def review_proposal(runs, proposal_id, expected_hash, expected_version, decision, reviewer, request_id):
    for value in (proposal_id, reviewer, request_id):
        identifier(value)
    positive_integer(expected_version)
    if decision not in ("approve", "reject"):
        raise ReviewError("invalid_review_decision")
    request_hash = digest({"proposal": proposal_id, "hash": expected_hash, "version": expected_version,
                           "decision": decision, "reviewer": reviewer})
    result = None
    with runs.db:
        runs.db.execute("BEGIN IMMEDIATE")
        saved = runs.db.execute("SELECT request_hash,result_json FROM reviews WHERE request_id=?", (request_id,)).fetchone()
        if saved:
            if saved[0] != request_hash:
                raise ReviewError("review_request_id_conflict")
            result = json.loads(saved[1])
        else:
            proposal = runs.db.execute("SELECT payload_hash,payload_json,state,version FROM proposals WHERE proposal_id=?",
                                       (proposal_id,)).fetchone()
            if proposal is None:
                raise ReviewError("unknown_proposal")
            payload = json.loads(proposal[1])
            registry = runs.db.execute("SELECT version,digest,context_json FROM current_snapshots WHERE case_id=?",
                                       (payload["case_id"],)).fetchone()
            current = None if registry is None else {"version": registry[0], "digest": registry[1], "context": json.loads(registry[2])}
            try:
                validate_review(payload, proposal[0], proposal[2], proposal[3], current,
                                expected_hash, expected_version, runs.clock())
                state = "APPROVED_SIMULATION" if decision == "approve" else "REJECTED"
                runs.db.execute("UPDATE proposals SET state=?,version=version+1 WHERE proposal_id=?", (state, proposal_id))
                result = {"ok": True, "state": state, "proposal_id": proposal_id,
                          "request_id": request_id, "reviewer": reviewer, "reviewed_at": iso(runs.clock()),
                          "execution_status": "NOT_IMPLEMENTED"}
            except ReviewError as exc:
                if exc.transition:
                    runs.db.execute("UPDATE proposals SET state=?,version=version+1 WHERE proposal_id=?",
                                    (exc.transition, proposal_id))
                result = {"ok": False, "reason": str(exc), "proposal_id": proposal_id,
                          "request_id": request_id, "reviewed_at": iso(runs.clock()),
                          "execution_status": "NOT_IMPLEMENTED"}
            runs.db.execute("INSERT INTO reviews VALUES(?,?,?,?)", (request_id, proposal_id, request_hash, canonical(result)))
            runs.audit("proposal_review", proposal_id, result)
    if not result["ok"]:
        raise ReviewError(result["reason"])
    return result
