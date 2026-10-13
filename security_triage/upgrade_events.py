"""Redacted structured event payloads. Never persist provider free text."""

import re
import json

SECRET = re.compile(r"(?i)(?:\bsk-[A-Za-z0-9_-]+|\bbearer\s+[^\s\"']+)")
PRIVATE_KEYS = {"authorization", "api_key", "ai_gateway_api_key", "token", "password", "secret", "reasoning", "reasoning_content"}


def redact(value, secrets=(), depth=0):
    if depth > 20:
        return "[DEPTH_LIMIT]"
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return SECRET.sub("[REDACTED]", value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if str(k).lower() in PRIVATE_KEYS:
                cleaned = "[REDACTED]"
            elif k == "arguments" and isinstance(v, str):
                # Native argument strings can otherwise hide sensitive dictionary keys.
                try:
                    from .contracts import strict_json
                    parsed = strict_json(v)
                    safe = redact(parsed, secrets, depth + 1)
                    cleaned = v if safe == parsed else json.dumps(safe, separators=(",", ":"))
                except ValueError:
                    cleaned = "[INVALID_ARGUMENTS]"
            else:
                cleaned = redact(v, secrets, depth + 1)
            result[redact(str(k), secrets, depth + 1)] = cleaned
        return result
    if isinstance(value, list):
        return [redact(v, secrets, depth + 1) for v in value]
    if value is None or type(value) in (int, bool, float):
        return value
    return "[INVALID_TYPE]"
