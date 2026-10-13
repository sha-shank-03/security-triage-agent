"""One owned stdlib HTTP child per request; no automatic retries."""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from .contracts import canonical
from .gateway import GatewayFailure


WINDOWS_RUNTIME_VARS = ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PROGRAMDATA",
                       "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP")


def child_environment(environ):
    """Keep Windows runtime paths; exclude credentials and Python/proxy overrides."""
    result = {name: environ[name] for name in WINDOWS_RUNTIME_VARS if name in environ}
    if os.name == "nt" and not all(result.get(name) for name in ("SYSTEMROOT", "SYSTEMDRIVE", "PROGRAMDATA", "LOCALAPPDATA")):
        raise GatewayFailure("windows_runtime_environment_missing")
    result["PYTHONIOENCODING"] = "utf-8"
    return result


class ChildTransport:
    def __init__(self, config, *, local_port=None, key_loader=None, monotonic=time.monotonic):
        self.config, self.local_port, self.key_loader, self.monotonic = config, local_port, key_loader, monotonic
        self.last_cleanup = {"owned_children": [], "cleanup_seconds": 0, "completed": True}
        if config.mode == "LOCAL_DOUBLE":
            if type(local_port) is not int or not 1 <= local_port <= 65535 or key_loader is not None:
                raise GatewayFailure("invalid_local_transport")
        elif local_port is not None or not callable(key_loader):
            raise GatewayFailure("main_runtime_loader_required")

    def send(self, request, deadline, cancelled):
        if cancelled():
            raise GatewayFailure("cancel_requested")
        if self.monotonic() >= deadline:
            raise GatewayFailure("deadline_exhausted")
        self.config.authorize(datetime.now(timezone.utc))
        try:
            key = self.key_loader() if self.config.mode == "LIVE" else None
        except Exception:
            raise GatewayFailure("runtime_key_unavailable") from None
        if self.config.mode == "LIVE" and (not isinstance(key, str) or not key or '\r' in key or '\n' in key):
            raise GatewayFailure("runtime_key_unavailable")
        job = {"mode": self.config.mode, "port": self.local_port, "request": request,
               "response_bytes": self.config.response_bytes, "key": key,
               "seconds": max(0.001, deadline - self.monotonic())}
        # The secret travels through a private stdin pipe, never argv/env/logs.
        child_env = child_environment(os.environ)
        try:
            proc = subprocess.Popen([sys.executable, "-m", "security_triage.transport_worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env)
        except OSError:
            raise GatewayFailure("transport_start_failed") from None
        self.last_cleanup = {"owned_children": [proc.pid], "cleanup_seconds": None, "completed": False}
        pending = canonical(job).encode('utf-8')
        try:
            while True:
                if cancelled():
                    raise GatewayFailure("cancel_requested", ambiguous=True)
                if self.monotonic() >= deadline:
                    raise GatewayFailure("deadline_exhausted", ambiguous=True)
                try:
                    stdout, _ = proc.communicate(pending, timeout=min(0.05, max(0.001, deadline - self.monotonic())))
                    break
                except subprocess.TimeoutExpired:
                    pending = None
            if proc.returncode != 0 or len(stdout) > self.config.response_bytes * 6 + 4096:
                raise GatewayFailure("transport_response_lost", ambiguous=True)
            result = json.loads(stdout.decode('utf-8'))
            if result.get("error"):
                allowed = {"response_byte_budget", "sensitive_response_blocked"}
                raise GatewayFailure(result["error"] if result["error"] in allowed else "transport_response_lost", ambiguous=True)
            if type(result.get("status")) is not int or not isinstance(result.get("body"), str):
                raise GatewayFailure("transport_invalid_result", ambiguous=True)
            return result["status"], result["body"]
        except GatewayFailure:
            raise
        except (OSError, ValueError, UnicodeError, KeyError, TypeError):
            raise GatewayFailure("transport_response_lost", ambiguous=True) from None
        finally:
            started = self.monotonic()
            try:
                if proc.poll() is None:
                    proc.kill()  # Popen owns the process handle; no global PID/name killing.
                proc.communicate(timeout=2)
                complete = proc.poll() is not None
            except (OSError, subprocess.TimeoutExpired):
                complete = False
            self.last_cleanup = {"owned_children": [] if complete else [proc.pid],
                                 "cleanup_seconds": max(0, self.monotonic() - started), "completed": complete}
            if not complete:
                raise GatewayFailure("owned_child_cleanup_failed", ambiguous=True)
