"""Host-owned support checks. No evaluation labels or provider decisions imported."""

from .contracts import ContractError, keys, positive_integer, timestamp

CLAIM_FIELDS = {
    "AUTH_SUCCESS": ("auth", "outcome", "success"),
    "MFA_DENIED": ("auth", "mfa", "denied"),
    "DEVICE_MANAGED": ("device", "managed", None),
    "NETWORK_APPROVED": ("network", "approved", None),
    "TRAVEL_APPROVED": ("travel", "approved", None),
    "RESOURCE_SENSITIVE": ("resource", "sensitive", None),
    "COVERAGE_COMPLETE": ("coverage", "complete", None),
}
REASONS = {"corroborated_benign_context", "supported_account_misuse", "insufficient_evidence"}
HYPOTHESES = {"APPROVED_NETWORK", "APPROVED_TRAVEL", "UNAUTHORIZED_ACCOUNT_USE", "MISSING_TELEMETRY"}


def claim(kind, record):
    field = CLAIM_FIELDS[kind][1]
    expected = CLAIM_FIELDS[kind][2]
    value = record["data"][field] if expected is None else record["data"][field] == expected
    return {"kind": kind, "record_id": record["id"],
            "record_version": record["version"], "value": value}


def adverse_sequence(records, success):
    """At least two denials within an hour before success, same IP/device."""
    data = success["data"]
    before = timestamp(success["event_time"])
    unique = {r["id"]: r for r in records}
    return [r for r in unique.values() if r["kind"] == "auth" and r["data"]["mfa"] == "denied"
            and r["data"]["ip"] == data["ip"] and r["data"]["device_id"] == data["device_id"]
            and 0 <= (before - timestamp(r["event_time"])).total_seconds() <= 3600]


def validate_final(final, tools):
    keys(final, ("disposition", "urgency", "claims", "gaps", "hypotheses", "reason", "proposal"))
    if final["disposition"] not in ("BENIGN", "ESCALATE", "INCONCLUSIVE"):
        raise ContractError("invalid_disposition")
    if final["urgency"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ContractError("invalid_urgency")
    if not isinstance(final["reason"], str) or final["reason"] not in REASONS:
        raise ContractError("invalid_reason")
    if not isinstance(final["claims"], list) or not 1 <= len(final["claims"]) <= 12:
        raise ContractError("invalid_claim_count")
    supported = {}
    for item in final["claims"]:
        keys(item, ("kind", "record_id", "record_version", "value"))
        positive_integer(item["record_version"])
        if type(item["value"]) is not bool or not isinstance(item["kind"], str):
            raise ContractError("invalid_claim_type")
        if not isinstance(item["record_id"], str):
            raise ContractError("invalid_reference")
        record = tools.seen.get(item["record_id"])
        if not record or record["version"] != item["record_version"]:
            raise ContractError("unseen_or_stale_reference")
        spec = CLAIM_FIELDS.get(item["kind"])
        if not spec or record["kind"] != spec[0] or claim(item["kind"], record) != item:
            raise ContractError("unsupported_claim")
        key = (item["kind"], item["record_id"])
        if key in supported:
            raise ContractError("duplicate_claim")
        supported[key] = record
    if not isinstance(final["gaps"], list) or len(final["gaps"]) > 4:
        raise ContractError("invalid_gaps")
    for gap in final["gaps"]:
        if not isinstance(gap, str) or ("COVERAGE_COMPLETE", gap) not in supported:
            raise ContractError("unsupported_gap")
        if supported[("COVERAGE_COMPLETE", gap)]["data"]["complete"]:
            raise ContractError("complete_record_not_gap")
    if not isinstance(final["hypotheses"], list) or not 1 <= len(final["hypotheses"]) <= 3:
        raise ContractError("invalid_hypotheses")
    if any(not isinstance(h, str) or h not in HYPOTHESES for h in final["hypotheses"]):
        raise ContractError("invalid_hypothesis")
    known_gaps = {r["id"] for r in tools.seen.values()
                  if r["kind"] == "coverage" and not r["data"]["complete"]}
    if known_gaps - set(final["gaps"]):
        raise ContractError("omitted_known_gap")
    successes = [r for (kind, _), r in supported.items() if kind == "AUTH_SUCCESS"
                 and r["data"]["outcome"] == "success"]
    adverse = False
    suspicious_successes = []
    for success in successes:
        denials = adverse_sequence(supported.values(), success)
        sensitive = any(kind == "RESOURCE_SENSITIVE" and r["data"]["sensitive"]
                        and r["data"]["session_id"] == success["data"]["session_id"]
                        for (kind, _), r in supported.items())
        unmanaged = any(kind == "DEVICE_MANAGED" and not r["data"]["managed"]
                        and r["data"]["device_id"] == success["data"]["device_id"]
                        for (kind, _), r in supported.items())
        if len(denials) >= 2 or (sensitive and unmanaged):
            adverse = True
            suspicious_successes.append(success)
    snapshot = tools.store.snapshot
    ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    if final["disposition"] == "BENIGN":
        if final["proposal"] is not None or known_gaps or not successes:
            raise ContractError("unsafe_benign_disposition")
        for kind in ("auth", "resource"):
            reads = tools.complete_event_read(kind)
            coverage = [r for (k, _), r in supported.items() if k == "COVERAGE_COMPLETE"
                        and r["data"]["stream"] == kind and r["data"]["complete"]
                        and timestamp(r["data"]["from"]) <= timestamp(snapshot["window_start"])
                        and timestamp(r["data"]["to"]) >= timestamp(snapshot["cutoff"])]
            if not reads or not coverage:
                raise ContractError("incomplete_benign_investigation")
        success = successes[-1]
        managed = any(k == "DEVICE_MANAGED" and r["data"]["managed"]
                      and r["data"]["device_id"] == success["data"]["device_id"]
                      for (k, _), r in supported.items())
        approved = any(k in ("NETWORK_APPROVED", "TRAVEL_APPROVED") and r["data"]["approved"]
                       and r["data"]["ip"] == success["data"]["ip"]
                       for (k, _), r in supported.items())
        visible = list(tools.seen.values())
        if (not managed or not approved or success["data"]["mfa"] != "satisfied"
                or any(r["kind"] == "auth" and r["data"]["mfa"] == "denied" for r in visible)
                or any(r["kind"] == "resource" and r["data"]["sensitive"] for r in visible)):
            raise ContractError("unresolved_adverse_evidence")
        if any(r["kind"] == "auth" and r["data"]["outcome"] == "success"
               and (r["data"]["device_id"] != success["data"]["device_id"]
                    or r["data"]["ip"] != success["data"]["ip"]
                    or r["data"]["mfa"] != "satisfied") for r in visible):
            raise ContractError("unresolved_other_success")
        if final["reason"] != "corroborated_benign_context":
            raise ContractError("reason_disposition_mismatch")
    elif final["disposition"] == "ESCALATE":
        if not adverse or final["reason"] != "supported_account_misuse":
            raise ContractError("unsupported_escalation")
        identities = [r for r in tools.seen.values() if r["kind"] == "identity"]
        if len(identities) != 1:
            raise ContractError("missing_identity_context")
        floor = "CRITICAL" if identities[0]["data"]["privileged"] else "HIGH"
        if ranks[final["urgency"]] < ranks[floor]:
            raise ContractError("urgency_below_policy_floor")
    else:
        if final["proposal"] is not None or final["reason"] != "insufficient_evidence":
            raise ContractError("inconclusive_proposal_or_reason")
        if ranks[final["urgency"]] < ranks[snapshot["alert"]["priority"]]:
            raise ContractError("urgency_below_alert_floor")
    proposal = final["proposal"]
    if proposal is not None:
        if final["disposition"] != "ESCALATE":
            raise ContractError("proposal_requires_escalation")
        keys(proposal, ("action", "target_session_id", "target_record_id", "target_record_version"))
        if proposal["action"] != "REVOKE_SESSION":
            raise ContractError("unsupported_proposal_action")
        if not any(proposal["target_record_id"] == r["id"]
                   and type(proposal["target_record_version"]) is int
                   and proposal["target_record_version"] == r["version"]
                   and proposal["target_session_id"] == r["data"]["session_id"] for r in suspicious_successes):
            raise ContractError("proposal_target_not_supported")
    return {**final, "execution_status": "NOT_IMPLEMENTED", "stop_reason": "validated_finish"}
