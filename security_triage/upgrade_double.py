"""Synthetic native-HTTP contract double. Never represents real model quality."""

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

from .contracts import canonical


def completion(tool, arguments, seq=1):
    return {"id": "double-generation-" + str(seq), "model": "local/contract-double", "choices": [{
        "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
            "tool_calls": [{"id": "call-" + str(seq), "type": "function", "function": {"name": tool, "arguments": canonical(arguments)}}]}}]}


def next_completion(request):
    observations = [json.loads(m["content"]) for m in request["messages"] if m["role"] == "tool"]
    seen = {r["id"]: r for o in observations for r in o["records"]}
    names = {o["tool"] for o in observations}
    seq = 1 + len([m for m in request["messages"] if m["role"] == "assistant"])
    if "get_identity_context" not in names:
        return completion("get_identity_context", {}, seq)
    if not any(o["tool"] == "search_events" and o["arguments"] == {"kind": "auth"} for o in observations):
        return completion("search_events", {"kind": "auth"}, seq)
    successes = [r for r in seen.values() if r["kind"] == "auth" and r["data"]["outcome"] == "success"]
    if successes and "get_device_context" not in names:
        return completion("get_device_context", {"device_id": successes[-1]["data"]["device_id"]}, seq)
    if successes and "get_network_context" not in names:
        return completion("get_network_context", {"ip": successes[-1]["data"]["ip"]}, seq)
    if not any(o["tool"] == "search_events" and o["arguments"] == {"kind": "resource"} for o in observations):
        return completion("search_events", {"kind": "resource"}, seq)
    if "get_telemetry_status" not in names:
        return completion("get_telemetry_status", {}, seq)
    # Deliberately limited imitation, only to exercise native continuation/guards.
    from .policy import CLAIM_FIELDS, claim, adverse_sequence
    claims = [claim(k, r) for r in seen.values() for k, spec in CLAIM_FIELDS.items() if r["kind"] == spec[0]]
    adverse = any(len(adverse_sequence(seen.values(), s)) >= 2 for s in successes)
    gaps = [r["id"] for r in seen.values() if r["kind"] == "coverage" and not r["data"]["complete"]]
    alert = json.loads(request["messages"][1]["content"])["alert"]
    privileged = any(r["kind"] == "identity" and r["data"]["privileged"] for r in seen.values())
    final = {"disposition": "ESCALATE" if adverse else "INCONCLUSIVE", "urgency": ("CRITICAL" if privileged else "HIGH") if adverse else alert["priority"],
        "claims": claims[:12], "gaps": gaps, "hypotheses": ["UNAUTHORIZED_ACCOUNT_USE" if adverse else "MISSING_TELEMETRY"],
        "reason": "supported_account_misuse" if adverse else "insufficient_evidence", "proposal": None}
    return completion("finish_investigation", final, seq)


@contextmanager
def local_server(scenario="branch-after-observation"):
    stats = {"requests": 0, "authorization_present": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            stats["requests"] += 1
            stats["authorization_present"] |= "Authorization" in self.headers
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/v1/chat/completions" or length > 98304:
                self.send_error(400)
                return
            request = json.loads(self.rfile.read(length))
            if scenario == "slow-headers":
                time.sleep(1)
            status = int(scenario.split('-')[1]) if scenario.startswith('http-') else 200
            body = canonical(next_completion(request)).encode('utf-8')
            if scenario == "malformed":
                body = b'{'
            elif scenario == "unknown-tool":
                body = canonical(completion("execute_shell", {"command": "ignored"})).encode('utf-8')
            elif scenario == "oversized":
                body = b'x' * 65537
            elif scenario == "response-loss":
                self.close_connection = True
                return
            elif scenario == "false-completion":
                body = canonical(completion("finish_investigation", {"disposition": "BENIGN", "urgency": "LOW", "claims": [], "gaps": [], "hypotheses": ["APPROVED_NETWORK"], "reason": "corroborated_benign_context", "proposal": None}, stats["requests"])).encode('utf-8')
            try:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if scenario == "slow-body":
                    time.sleep(1)
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server.server_port, stats
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
