"""Scripted adaptive policy. This is deterministic code, not model inference."""

from .contracts import PROVIDER_VERSION, canonical
from .policy import adverse_sequence, claim


def finish_from_observations(conversation):
    observations = [m["observation"] for m in conversation if m["role"] == "tool"]
    rows = {r["id"]: r for o in observations for r in o["records"]}
    coverage = [r for r in rows.values() if r["kind"] == "coverage"]
    gaps = [r["id"] for r in coverage if not r["data"]["complete"]]
    claims = [claim("COVERAGE_COMPLETE", r) for r in coverage]
    result = {"disposition": "INCONCLUSIVE", "urgency": conversation[1]["alert"]["priority"],
              "claims": claims, "gaps": gaps, "hypotheses": ["MISSING_TELEMETRY"],
              "reason": "insufficient_evidence", "proposal": None}
    successes = [r for r in rows.values() if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
    if gaps or len({r["data"]["stream"] for r in coverage}) != 2 or not successes:
        return result
    success = successes[-1]
    data = success["data"]
    denials = adverse_sequence(rows.values(), success)
    devices = [r for r in rows.values() if r["kind"] == "device" and r["data"]["device_id"] == data["device_id"]]
    contexts = [r for r in rows.values() if r["kind"] in ("network", "travel") and r["data"]["ip"] == data["ip"]]
    resources = [r for r in rows.values() if r["kind"] == "resource"]
    claims.append(claim("AUTH_SUCCESS", success))
    claims.extend(claim("MFA_DENIED", r) for r in denials[:2])
    claims.extend(claim("DEVICE_MANAGED", r) for r in devices[:1])
    claims.extend(claim("NETWORK_APPROVED" if r["kind"] == "network" else "TRAVEL_APPROVED", r)
                  for r in contexts[:2])
    claims.extend(claim("RESOURCE_SENSITIVE", r) for r in resources[:3])
    result["hypotheses"] = ["APPROVED_TRAVEL" if any(r["kind"] == "travel" for r in contexts)
                            else "APPROVED_NETWORK", "UNAUTHORIZED_ACCOUNT_USE"]
    sensitive = any(r["data"]["sensitive"] and r["data"]["session_id"] == data["session_id"] for r in resources)
    unmanaged = any(not r["data"]["managed"] for r in devices)
    if len(denials) >= 2 or (sensitive and unmanaged):
        # Include a sensitive record from the exact target session, even on a crowded page.
        if sensitive and not any(c["kind"] == "RESOURCE_SENSITIVE" and c["value"]
                                 and rows[c["record_id"]]["data"]["session_id"] == data["session_id"] for c in claims):
            claims.append(claim("RESOURCE_SENSITIVE", next(r for r in resources
                          if r["data"]["sensitive"] and r["data"]["session_id"] == data["session_id"])))
        privileged = any(r["kind"] == "identity" and r["data"]["privileged"] for r in rows.values())
        result.update(disposition="ESCALATE", urgency="CRITICAL" if privileged else "HIGH",
                      reason="supported_account_misuse", proposal={"action": "REVOKE_SESSION",
                          "target_session_id": data["session_id"], "target_record_id": success["id"],
                          "target_record_version": success["version"]})
    elif (any(r["data"]["managed"] for r in devices) and any(r["data"]["approved"] for r in contexts)
          and data["mfa"] == "satisfied" and not any(r["data"]["sensitive"] for r in resources)
          and not any(r["kind"] == "auth" and r["data"]["mfa"] == "denied" for r in rows.values())):
        result.update(disposition="BENIGN", urgency="LOW", reason="corroborated_benign_context")
    return result


class ScriptedInvestigator:
    name = PROVIDER_VERSION
    configuration = {"name": PROVIDER_VERSION, "mode": "scripted", "model": None}

    def next_turn(self, conversation, tool_schemas, remaining_budget):
        observations = [m["observation"] for m in conversation if m["role"] == "tool"]
        rows = {r["id"]: r for o in observations for r in o["records"]}

        def asked(name, args):
            return any(o["tool"] == name and o["arguments"] == args for o in observations)

        def call(name, args=None):
            return canonical({"tool": name, "arguments": args or {}})

        def event_query(args):
            chain = [o for o in observations if o["tool"] == "search_events"
                     and {k: v for k, v in o["arguments"].items() if k != "cursor"} == args]
            if not chain:
                return call("search_events", args)
            if chain[-1]["next_cursor"]:
                return call("search_events", {**args, "cursor": chain[-1]["next_cursor"]})
            return None

        if not asked("get_identity_context", {}):
            return call("get_identity_context")
        query = event_query({"kind": "auth"})
        if query:
            return query
        if not asked("get_telemetry_status", {}):
            return call("get_telemetry_status")
        coverage = [r for r in rows.values() if r["kind"] == "coverage"]
        successes = [r for r in rows.values() if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
        if any(not r["data"]["complete"] for r in coverage) or not successes:
            return call("finish_investigation", finish_from_observations(conversation))
        data = successes[-1]["data"]
        suspicious = len(adverse_sequence(rows.values(), successes[-1])) >= 2
        order = [("get_device_context", {"device_id": data["device_id"]}),
                 ("get_network_context", {"ip": data["ip"]})]
        if not suspicious:
            order.reverse()
        for name, arguments in order:
            if not asked(name, arguments):
                return call(name, arguments)
        if not suspicious and not any(r["kind"] == "network" and r["data"]["approved"] for r in rows.values()):
            if not asked("get_travel_context", {"ip": data["ip"]}):
                return call("get_travel_context", {"ip": data["ip"]})
        query = event_query({"kind": "resource", **({"session_id": data["session_id"]} if suspicious else {})})
        if query:
            return query
        return call("finish_investigation", finish_from_observations(conversation))

