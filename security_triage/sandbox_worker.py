"""Private stdlib GET child; fixed authority, no redirects, proxy or write verb."""

import http.client
import json
import math
import re
import sys

from .sandbox import API_VERSION, SandboxConfig

SAFE_HEADERS = {"content-type", "link", "retry-after", "x-ratelimit-remaining",
                "x-ratelimit-reset", "x-github-api-version-selected"}


def execute(job):
    config = SandboxConfig.from_dict(job["config"])
    path, seconds, token = job["path"], job["seconds"], job["token"]
    if path not in config.allowed_paths() or type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 60:
        raise ValueError("invalid_job")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
               "User-Agent": "security-triage-sandbox-u2a"}
    if config.mode == "REAL_SANDBOX" and job["port"] is None and isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_]{8,4096}", token):
        connection = http.client.HTTPSConnection("api.github.com", 443, timeout=seconds)
        headers["Authorization"] = "Bearer " + token
    elif config.mode == "LOCAL_DOUBLE" and token is None and type(job["port"]) is int and 1 <= job["port"] <= 65535:
        connection = http.client.HTTPConnection("127.0.0.1", job["port"], timeout=seconds)
    else:
        raise ValueError("invalid_mode")
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        safe = {}
        for key, value in response.getheaders():
            key = key.lower()
            if key in SAFE_HEADERS:
                if key in safe or len(value) > 4096:
                    return {"error": "header_byte_budget"}
                safe[key] = value
        if sum(len(k) + len(v) for k, v in safe.items()) > 8192:
            return {"error": "header_byte_budget"}
        # Non200 body is discarded without consuming a potentially unbounded stream.
        data = response.read(config.response_bytes + 1) if response.status == 200 else b""
        if len(data) > config.response_bytes:
            return {"error": "response_byte_budget"}
        if token is not None and (token.encode("utf-8") in data or any(token in v for v in safe.values())):
            return {"error": "sensitive_response_blocked"}
        return {"status": response.status, "headers": safe, "body": data.decode("utf-8")}
    finally:
        connection.close()


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError("job_byte_budget")
        result = execute(json.loads(raw.decode("utf-8")))
    except Exception:
        result = {"error": "transport_failure"}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
