"""Owned local protocol double; importing this module starts no server."""

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer


@contextmanager
def protocol_double(replies):
    observed = []
    pending = list(replies)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/api/chat" or not 0 < size <= 98304:
                self.send_error(400)
                return
            observed.append(json.loads(self.rfile.read(size)))
            item = pending.pop(0) if pending else (500, b"{}")
            status, payload = item[:2]
            if len(item) == 3:
                if not 0 <= item[2] <= 2:
                    raise ValueError("test_double_delay_budget")
                time.sleep(item[2])
            if not isinstance(payload, bytes):
                payload = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # A bounded client timeout may have already closed its owned connection.

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], observed
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise RuntimeError("owned_http_double_did_not_stop")
