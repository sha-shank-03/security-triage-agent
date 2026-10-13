"""Complete-playbook-v2: fixed observation workflow; no fixture/label access."""

import json
import time

from .contracts import ContractError, canonical, timestamp
from .policy import adverse_sequence, claim

VERSION = "complete-playbook-v2-u2b-v1"


def next_call(initial, observations):
    """Only permitted initial alert/window and past tool observations enter policy."""
    seen = {r["id"]: r for o in observations for r in o["records"]}
    rows = sorted(seen.values(), key=lambda r: (r["event_time"], r["id"]))
    names = {o["tool"] for o in observations}
    if "get_identity_context" not in names:
        return "get_identity_context", {}
    for stream in ("auth", "resource"):
        reads = [o for o in observations if o["tool"] == "search_events"
                 and {k: v for k, v in o["arguments"].items() if k != "cursor"} == {"kind": stream}]
        if not reads:
            return "search_events", {"kind": stream}
        if reads[-1]["next_cursor"]:
            return "search_events", {"kind": stream, "cursor": reads[-1]["next_cursor"]}
    if "get_telemetry_status" not in names:
        return "get_telemetry_status", {}
    successes = [r for r in rows if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
    queried = lambda tool, field, value: any(o["tool"] == tool and o["arguments"].get(field) == value for o in observations)
    for success in successes:
        device, ip = success["data"]["device_id"], success["data"]["ip"]
        if not queried("get_device_context", "device_id", device):
            return "get_device_context", {"device_id": device}
        if not queried("get_network_context", "ip", ip):
            return "get_network_context", {"ip": ip}
        approved = any(r["kind"] == "network" and r["data"]["ip"] == ip and r["data"]["approved"] for r in rows)
        if not approved and not queried("get_travel_context", "ip", ip):
            return "get_travel_context", {"ip": ip}
    return "finish_investigation", decide(initial, rows, observations)


def decide(initial, rows, observations):
    gaps = [r for r in rows if r["kind"] == "coverage" and not r["data"]["complete"]]
    selected = []
    def add(kind, record):
        item = claim(kind, record)
        if item not in selected:
            selected.append(item)
    for row in rows:
        if row["kind"] == "coverage":
            add("COVERAGE_COMPLETE", row)
    successes = [r for r in rows if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
    adverse = None
    for success in successes:
        denials = adverse_sequence(rows, success)
        unmanaged = [r for r in rows if r["kind"] == "device" and not r["data"]["managed"]
                     and r["data"]["device_id"] == success["data"]["device_id"]]
        sensitive = [r for r in rows if r["kind"] == "resource" and r["data"]["sensitive"]
                     and r["data"]["session_id"] == success["data"]["session_id"]]
        if len(denials) >= 2 or unmanaged and sensitive:
            adverse = success
            add("AUTH_SUCCESS", success)
            if len(denials) >= 2:
                for denial in denials[-2:]: add("MFA_DENIED", denial)
            else:
                add("DEVICE_MANAGED", unmanaged[-1]); add("RESOURCE_SENSITIVE", sensitive[-1])
            break  # Positive evidence outranks missing telemetry.
    coverage_ok = all(any(r["kind"] == "coverage" and r["data"]["stream"] == stream and r["data"]["complete"]
                         and timestamp(r["data"]["from"]) <= timestamp(initial["window_start"])
                         and timestamp(r["data"]["to"]) >= timestamp(initial["cutoff"]) for r in rows)
                      for stream in ("auth", "resource"))
    pages_closed = all(any(o["tool"] == "search_events" and not o["truncated"]
                           and {k: v for k, v in o["arguments"].items() if k != "cursor"} == {"kind": stream}
                           for o in observations) for stream in ("auth", "resource"))
    benign = bool(successes) and not gaps and coverage_ok and pages_closed
    benign = benign and not any(r["kind"] == "auth" and r["data"]["mfa"] == "denied" or
                                r["kind"] == "resource" and r["data"]["sensitive"] for r in rows)
    if successes:
        last = successes[-1]
        benign = benign and all(s["data"]["device_id"] == last["data"]["device_id"] and
                               s["data"]["ip"] == last["data"]["ip"] and s["data"]["mfa"] == "satisfied" for s in successes)
        managed = [r for r in rows if r["kind"] == "device" and r["data"]["managed"]
                   and r["data"]["device_id"] == last["data"]["device_id"]]
        approved = [r for r in rows if r["kind"] in ("network", "travel") and r["data"]["approved"]
                    and r["data"]["ip"] == last["data"]["ip"]]
        benign = benign and bool(managed and approved)
        if adverse is None:
            add("AUTH_SUCCESS", last)
            if managed: add("DEVICE_MANAGED", managed[-1])
            if approved: add("NETWORK_APPROVED" if approved[-1]["kind"] == "network" else "TRAVEL_APPROVED", approved[-1])
    if adverse is not None:
        privileged = any(r["kind"] == "identity" and r["data"]["privileged"] for r in rows)
        disposition, urgency, hypothesis, reason = "ESCALATE", "CRITICAL" if privileged else "HIGH", "UNAUTHORIZED_ACCOUNT_USE", "supported_account_misuse"
    elif benign:
        disposition, urgency, hypothesis, reason = "BENIGN", initial["alert"]["priority"], "APPROVED_NETWORK", "corroborated_benign_context"
    else:
        disposition, urgency, hypothesis, reason = "INCONCLUSIVE", initial["alert"]["priority"], "MISSING_TELEMETRY", "insufficient_evidence"
    return {"disposition": disposition, "urgency": urgency, "claims": selected[:12], "gaps": [r["id"] for r in gaps],
            "hypotheses": [hypothesis], "reason": reason, "proposal": None}


class PlaybookTransport:
    """Synthetic native packet adapter; same U1 host/catalog/config/guards/budget."""
    def __init__(self, *, monotonic=time.monotonic):
        self.monotonic = monotonic
        self.last_cleanup = {"owned_children": [], "cleanup_seconds": 0, "completed": True}

    def send(self, request, deadline, cancelled):
        if cancelled(): raise ContractError("cancel_requested")
        if self.monotonic() >= deadline: raise ContractError("deadline_exhausted")
        if request["model"] != "local/contract-double": raise ContractError("baseline_local_only")
        initial = json.loads(request["messages"][1]["content"])
        if set(initial) != {"alert", "window_start", "cutoff"}: raise ContractError("baseline_input_boundary")
        observations = [json.loads(m["content"]) for m in request["messages"] if m["role"] == "tool"]
        tool, arguments = next_call(initial, observations)
        seq = 1 + sum(m["role"] == "assistant" for m in request["messages"])
        packet = {"id": "playbook-generation-" + str(seq), "model": "local/contract-double", "choices": [{"finish_reason": "tool_calls",
                  "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "playbook-call-" + str(seq), "type": "function",
                  "function": {"name": tool, "arguments": canonical(arguments)}}]}}]}
        return 200, canonical(packet)
