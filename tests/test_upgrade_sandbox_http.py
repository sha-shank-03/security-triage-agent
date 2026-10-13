"""Prepared local HTTP/owned-child batch. Requires a heavy lease; U2A unexecuted."""

import json
import socket
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from security_triage.sandbox import SandboxFailure, SandboxReader
from security_triage.sandbox_transport import SandboxChildTransport
from tests.test_upgrade_sandbox import sample


@contextmanager
def double(handler):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            received.append(("GET", self.path, dict(self.headers)))
            handler(self)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise AssertionError("owned local server did not stop")


def reply(request, value, *, status=200, headers=None, slow=False):
    data = json.dumps(value).encode("utf-8")
    try:
        request.send_response(status)
        request.send_header("Content-Type", "application/json")
        request.send_header("Content-Length", str(len(data)))
        for key, val in (headers or {}).items():
            request.send_header(key, val)
        request.end_headers()
        if slow:
            request.wfile.write(data[:1]); request.wfile.flush(); time.sleep(0.7)
            request.wfile.write(data[1:])
        else:
            request.wfile.write(data)
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        pass


class SandboxHTTP(unittest.TestCase):
    def test_complete_read_over_owned_http_child_is_get_only(self):
        config, repository, issue, comment = sample("LOCAL_DOUBLE", deadline=10)
        def handle(request):
            values = {"/installation/repositories?per_page=2&page=1": {"total_count": 1, "repositories": [repository]},
                      config.repo_path: repository, config.repo_path + "/issues/3": issue,
                      config.repo_path + "/issues/3/comments?per_page=50&page=1": [comment]}
            reply(request, values[request.path])
        with double(handle) as (port, received):
            transport = SandboxChildTransport(config, local_port=port)
            value = SandboxReader(config, transport).read_case(3)
            self.assertEqual((value["writes"], value["requests"]), (0, 5))
            self.assertEqual(len(received), 5)
            self.assertTrue(all(method == "GET" and "Authorization" not in headers for method, _, headers in received))
            self.assertTrue(transport.last_cleanup["completed"])
            self.assertEqual(transport.last_cleanup["owned_children"], [])

    def test_http_errors_return_once_with_no_redirect_or_retry(self):
        config, *_ = sample("LOCAL_DOUBLE", deadline=10)
        for status, code in [(401, "authentication_failed"), (403, "forbidden"), (404, "not_found"),
                             (429, "rate_limited"), (503, "service_failure"), (301, "redirect_rejected")]:
            with self.subTest(status=status), double(lambda request: reply(request, "private error", status=status,
                     headers={"Location": "https://evil.invalid/", "Retry-After": "120"} if status == 429 else {})) as (port, received):
                transport = SandboxChildTransport(config, local_port=port)
                reader = SandboxReader(config, transport)
                with self.assertRaises(SandboxFailure) as caught:
                    reader.read_case(3)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(received), 1)
                self.assertTrue(transport.last_cleanup["completed"])

    def test_total_deadline_bounds_header_and_body_stalls(self):
        config, *_ = sample("LOCAL_DOUBLE", deadline=0.4)
        def headers(request):
            time.sleep(0.7)
            reply(request, {})
        for handler in (headers, lambda request: reply(request, {"slow": "body"}, slow=True)):
            with double(handler) as (port, received):
                transport = SandboxChildTransport(config, local_port=port)
                began = time.monotonic()
                with self.assertRaises(SandboxFailure) as caught:
                    SandboxReader(config, transport).read_case(3)
                self.assertIn(caught.exception.code, {"deadline_exhausted", "transport_response_lost"})
                self.assertLess(time.monotonic() - began, 2.5)
                self.assertLessEqual(len(received), 1)
                self.assertEqual(transport.last_cleanup["owned_children"], [])

    def test_cancel_and_connection_loss_leave_no_child_or_replay(self):
        config, *_ = sample("LOCAL_DOUBLE", deadline=10)
        def lose(request):
            request.connection.shutdown(socket.SHUT_RDWR)
            request.connection.close()
        for handler, cancel in [(lose, False), (lambda request: reply(request, {"slow": "body"}, slow=True), True)]:
            with double(handler) as (port, received):
                transport = SandboxChildTransport(config, local_port=port)
                began = time.monotonic()
                reader = SandboxReader(config, transport, cancelled=lambda: cancel and time.monotonic() - began >= 0.3)
                with self.assertRaises(SandboxFailure) as caught:
                    reader.read_case(3)
                self.assertEqual(caught.exception.code, "cancel_requested" if cancel else "transport_response_lost")
                with self.assertRaises(SandboxFailure):
                    reader.read_case(3)
                self.assertLessEqual(len(received), 1)
                self.assertEqual(transport.last_cleanup["owned_children"], [])


if __name__ == "__main__":
    unittest.main()
