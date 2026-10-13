"""Owned GET-only transport. Real dispatch requires trusted short-lived attestation."""

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .contracts import canonical, timestamp
from .gateway import GatewayFailure
from .sandbox import SandboxFailure
from .upgrade_transport import child_environment


@dataclass(frozen=True)
class RuntimeCredential:
    """Main loader supplies this object; API cannot attest token installation ID."""

    token: str = field(repr=False, compare=False)
    app_id: int
    installation_id: int
    account_id: int
    repository_ids: tuple
    permissions: tuple
    expires_at: str
    config_sha256: str
    dispatch_id: str

    def check(self, config, now):
        try:
            expiry = timestamp(self.expires_at)
            if (not isinstance(self.token, str) or not re.fullmatch(r"[A-Za-z0-9_]{8,4096}", self.token)
                    or self.app_id != config.app_id or type(self.app_id) is not int
                    or self.installation_id != config.installation_id or type(self.installation_id) is not int
                    or self.account_id != config.account_id or type(self.account_id) is not int
                    or self.repository_ids != (config.repository_id,)
                    or type(self.repository_ids[0]) is not int
                    or self.permissions != (("issues", "read"), ("metadata", "read"))
                    or self.config_sha256 != config.sha256
                    or not isinstance(self.dispatch_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.dispatch_id)
                    or not 0 < (expiry - now).total_seconds() <= 3600):
                raise SandboxFailure("runtime_identity_or_authority_mismatch")
        except (ValueError, TypeError, IndexError):
            raise SandboxFailure("runtime_identity_or_authority_mismatch") from None


class SandboxChildTransport:
    def __init__(self, config, *, local_port=None, credential=None, monotonic=time.monotonic,
                 utcnow=lambda: datetime.now(timezone.utc)):
        self.config, self.port, self.credential = config, local_port, credential
        self.clock, self.utcnow = monotonic, utcnow
        self._active = threading.Lock()
        self.last_cleanup = {"owned_children": [], "completed": True, "cleanup_seconds": 0}
        if config.mode == "LOCAL_DOUBLE":
            if type(local_port) is not int or not 1 <= local_port <= 65535 or credential is not None:
                raise SandboxFailure("invalid_local_transport")
        elif config.mode == "REAL_SANDBOX" and local_port is None and isinstance(credential, RuntimeCredential):
            credential.check(config, utcnow())
        else:
            raise SandboxFailure("trusted_runtime_credential_required")

    def send(self, path, deadline, cancelled):
        if not self._active.acquire(blocking=False):
            raise SandboxFailure("concurrent_transport_rejected")
        try:
            return self._send(path, deadline, cancelled)
        finally:
            self._active.release()

    def _send(self, path, deadline, cancelled):
        if path not in self.config.allowed_paths():
            raise SandboxFailure("route_not_allowed")
        if cancelled():
            raise SandboxFailure("cancel_requested")
        if self.clock() >= deadline:
            raise SandboxFailure("deadline_exhausted")
        if self.credential is not None:
            self.credential.check(self.config, self.utcnow())
        job = {"config": self.config.to_dict(), "port": self.port, "path": path,
               "token": self.credential.token if self.credential else None,
               "seconds": max(0.001, deadline - self.clock())}
        pending = canonical(job).encode("utf-8")
        if len(pending) > 16384:
            raise SandboxFailure("transport_job_budget")
        try:
            env = child_environment(os.environ)
            proc = subprocess.Popen([sys.executable, "-m", "security_triage.sandbox_worker"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        except (OSError, GatewayFailure):
            raise SandboxFailure("transport_start_failed") from None
        self.last_cleanup = {"owned_children": [proc.pid], "completed": False, "cleanup_seconds": None}
        try:
            while True:
                if cancelled():
                    raise SandboxFailure("cancel_requested")
                if self.clock() >= deadline:
                    raise SandboxFailure("deadline_exhausted")
                try:
                    stdout, _ = proc.communicate(pending, timeout=min(0.05, max(0.001, deadline - self.clock())))
                    break
                except subprocess.TimeoutExpired:
                    pending = None
            if proc.returncode != 0 or len(stdout) > self.config.response_bytes * 6 + 16384:
                raise SandboxFailure("transport_response_lost")
            value = json.loads(stdout.decode("utf-8"))
            if not isinstance(value, dict):
                raise SandboxFailure("transport_invalid_result")
            if value.get("error"):
                code = value["error"] if value["error"] in {"response_byte_budget", "sensitive_response_blocked", "header_byte_budget"} else "transport_response_lost"
                raise SandboxFailure(code)
            if type(value.get("status")) is not int or not isinstance(value.get("headers"), dict) or not isinstance(value.get("body"), str):
                raise SandboxFailure("transport_invalid_result")
            return value["status"], value["headers"], value["body"]
        except SandboxFailure:
            raise
        except (OSError, ValueError, UnicodeError, TypeError):
            raise SandboxFailure("transport_response_lost") from None
        finally:
            started = self.clock()
            try:
                if proc.poll() is None:
                    proc.kill()  # Popen-owned handle, no process-name/PID scan.
                proc.communicate(timeout=2)
                completed = proc.poll() is not None
            except (OSError, subprocess.TimeoutExpired):
                completed = False
            self.last_cleanup = {"owned_children": [] if completed else [proc.pid], "completed": completed,
                                 "cleanup_seconds": max(0, self.clock() - started)}
            if not completed:
                raise SandboxFailure("owned_child_cleanup_failed")
