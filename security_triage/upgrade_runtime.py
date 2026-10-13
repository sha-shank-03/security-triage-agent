"""Observation-driven U1 host. Transport failures halt; no containment tools."""

import json

from .contracts import ContractError, canonical, digest
from .gateway import (PROMPT, VERSION, GatewayFailure, continuation, decode_packet,
                      exchange, initial_messages, make_request, project_packet, tool_catalog)
from .policy import validate_final
from .tools import EvidenceTools
from .upgrade_events import redact


def versions(code_sha256):
    return {"code_sha256": code_sha256, "prompt_sha256": digest(PROMPT), "tools_sha256": digest(tool_catalog()), "protocol": VERSION}


def fallback(source, tools, reason):
    return {"disposition": "INCONCLUSIVE", "urgency": source["alert"]["priority"], "claims": [],
            "gaps": [r["id"] for r in tools.seen.values() if r["kind"] == "coverage" and not r["data"]["complete"]],
            "hypotheses": ["MISSING_TELEMETRY"], "reason": "host_fallback", "proposal": None,
            "execution_status": "NOT_IMPLEMENTED", "stop_reason": reason}


def investigate(evidence, state, config, transport, *, code_sha256, resume=False):
    state.start(evidence.snapshot, config, versions(code_sha256), resume=resume)
    if state.row()["state"] != "INVESTIGATING":
        return state.run_id
    tools = EvidenceTools(evidence)
    messages = initial_messages(evidence.snapshot)
    raw_final = None
    interrupted = False
    for attempt in state.history():
        if attempt["call_json"]:
            call = json.loads(attempt["call_json"])
            if call["tool"] == "finish_investigation":
                raw_final = call["arguments"]
        if attempt["observation_json"]:
            observation = json.loads(attempt["observation_json"])
            tools.remember(observation)
            continuation(messages, call, observation)
        elif attempt["reason"] == "REQUEST_STARTED":
            state.resolve(attempt["seq"], "interrupted_unknown_remote_outcome")
            interrupted = True
        elif attempt["reason"] != "validated_finish":
            messages.append({"role": "user", "content": canonical({"host_rejection": attempt["reason"]})})
    if interrupted:
        reason = "interrupted_unknown_remote_outcome"
        state.finish(raw_final, fallback(evidence.snapshot, tools, reason), reason)
        return state.run_id
    reason = "attempt_budget_exhausted"
    while True:
        seq = None
        try:
            state.check_active()
            request = make_request(messages, config)
            seq = state.reserve(request)
            raw = exchange(transport, request, config, state.deadline, lambda: bool(state.row()["cancelled"]))
            state.check_active()
            packet = project_packet(raw, config)
            state.record_packet(seq, packet)  # Durable before protocol/guard decisions.
            if redact(packet, state.secrets) != packet:
                raise GatewayFailure("sensitive_response_blocked")
            call = decode_packet(packet, config)
            if any(json.loads(h["call_json"])["id"] == call["id"] for h in state.history() if h["call_json"]):
                raise GatewayFailure("duplicate_native_call_id")
            state.record_call(seq, call)
            if call["tool"] == "finish_investigation":
                raw_final = call["arguments"]  # Persisted separately before guard.
                if raw_final.get("proposal") is not None:
                    raise ContractError("proposals_unavailable_u1")
                guarded = validate_final(raw_final, tools)
                state.check_active()
                state.finish(raw_final, guarded, "validated_finish", seq=seq)
                return state.run_id
            candidate = EvidenceTools(evidence)
            for previous in tools.observations:
                candidate.remember(previous)
            observation = candidate.call(call["tool"], call["arguments"])
            if len(canonical(observation).encode("utf-8")) > config.observation_bytes:
                raise ContractError("observation_byte_budget")
            state.check_active()
            state.resolve(seq, "evidence_read", observation)
            tools = candidate
            continuation(messages, call, observation)
        except GatewayFailure as exc:
            reason = exc.code
            if seq is not None:
                state.resolve(seq, reason)
            break  # Zero automatic inference transport retries or fallback.
        except ContractError as exc:
            reason = str(exc)
            if seq is not None:
                correction = reason not in ("deadline_exhausted", "cancel_requested")
                state.resolve(seq, reason, correction=correction)
            if seq is None or reason in ("deadline_exhausted", "cancel_requested"):
                break
            # Explicit host-feedback decision, distinct from replaying a failed transmission.
            messages.append({"role": "user", "content": canonical({"host_rejection": reason})})
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            reason = "invalid_protocol_value"
            if seq is not None:
                state.resolve(seq, reason, correction=True)
            break
    if state.row()["cancelled"]:
        reason = "cancel_requested"
    state.finish(raw_final, fallback(evidence.snapshot, tools, reason), reason)
    return state.run_id
