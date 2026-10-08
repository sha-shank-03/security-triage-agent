"""Native Ollama /api/chat adapter. Fixed loopback route; no model installation."""

import http.client
import socket
import time

from .contracts import ContractError, canonical, decode_turn, strict_json


def wire_request(model, conversation, catalog):
    messages = []
    for entry in conversation:
        role = entry["role"]
        if role == "assistant":
            call = entry["call"]
            messages.append({"role": "assistant", "content": "", "tool_calls": [{
                "type": "function", "function": {"name": call["tool"], "arguments": call["arguments"]}}]})
        elif role == "tool":
            observation = entry["observation"]
            messages.append({"role": "tool", "tool_name": observation["tool"], "content": canonical(observation)})
        else:
            messages.append({"role": "system" if role == "system" else "user",
                             "content": canonical({k: v for k, v in entry.items() if k != "role"})})
    request = {"model": model, "stream": False, "messages": messages,
               "tools": [{"type": "function", "function": item} for item in catalog],
               "options": {"temperature": 0, "num_predict": 1024}}
    encoded = canonical(request).encode("utf-8")
    if len(encoded) > 98304:
        raise ContractError("wire_request_byte_budget")
    return encoded


def wire_response(raw, catalog):
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ContractError("wire_response_encoding") from exc
    response = strict_json(raw)
    if not isinstance(response, dict) or response.get("done") is not True:
        raise ContractError("wire_response_not_complete")
    message = response.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ContractError("wire_response_missing_assistant")
    calls = message.get("tool_calls")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
        raise ContractError("wire_requires_one_tool_call")
    function = calls[0].get("function")
    if not isinstance(function, dict) or set(function) - {"name", "arguments", "index"}:
        raise ContractError("wire_invalid_function")
    if function.get("name") not in {s["name"] for s in catalog} or not isinstance(function.get("arguments"), dict):
        raise ContractError("wire_unknown_tool_or_arguments")
    turn = canonical({"tool": function["name"], "arguments": function["arguments"]})
    decode_turn(turn)
    usage = {}
    for field in ("prompt_eval_count", "eval_count", "total_duration"):
        value = response.get(field)
        if value is not None and (type(value) is not int or value < 0):
            raise ContractError("wire_invalid_usage")
        usage[field] = value
    # Deliberately ignore free text and any reasoning field; only the tool call is retained.
    return turn, usage


class OllamaProvider:
    name = "ollama_native_v1"

    def __init__(self, model, port=11434, *, transport=None, protocol_double=False):
        if (not isinstance(model, str) or not 1 <= len(model) <= 128
                or any(ord(c) < 32 for c in model)):
            raise ContractError("invalid_model_name")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ContractError("invalid_loopback_port")
        if type(protocol_double) is not bool:
            raise ContractError("invalid_protocol_double_marker")
        self.model, self.port = model, port
        self.transport = transport or self._post
        self.configuration = {"name": self.name, "model": model, "host": "127.0.0.1",
                              "port": port, "path": "/api/chat",
                              "mode": "protocol_double" if transport or protocol_double else "ollama_unverified_model"}
        self.last_usage = {}

    def _post(self, body, timeout):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.request("POST", "/api/chat", body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            payload = response.read(65537)
            if len(payload) > 65536:
                raise ContractError("wire_response_byte_budget")
            return response.status, payload
        finally:
            connection.close()

    def next_turn(self, conversation, tool_schemas, remaining_budget):
        self.last_usage = {"wire_requests": 0, "retries": 0, "prompt_eval_count": None,
                           "eval_count": None, "total_duration": None}
        remaining = remaining_budget.get("seconds", 0)
        deadline = time.monotonic() + max(0, remaining)
        cancelled = remaining_budget.get("cancelled", lambda: False)
        body = wire_request(self.model, conversation, tool_schemas)
        for attempt in range(2):
            seconds = deadline - time.monotonic()
            if cancelled():
                raise ContractError("cancel_requested")
            if seconds <= 0:
                raise ContractError("deadline_exhausted")
            self.last_usage["wire_requests"] += 1
            retryable = False
            try:
                status, raw = self.transport(body, min(15, seconds))
                retryable = status == 429 or 500 <= status <= 599
                if status == 200:
                    if cancelled():
                        raise ContractError("cancel_requested")
                    turn, usage = wire_response(raw, tool_schemas)
                    self.last_usage.update(usage)
                    return turn
                if not retryable:
                    raise ContractError("wire_http_status_" + str(status))
            except (socket.timeout, TimeoutError):
                retryable = True
            if not retryable or attempt == 1:
                raise ContractError("wire_retry_exhausted")
            if cancelled():
                raise ContractError("cancel_requested")
            if deadline - time.monotonic() <= 0.25:
                raise ContractError("deadline_exhausted")
            self.last_usage["retries"] += 1
            time.sleep(0.25)
        raise ContractError("wire_retry_exhausted")
