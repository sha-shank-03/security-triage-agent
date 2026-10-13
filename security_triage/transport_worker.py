"""Private transport child. Fixed live authority; bounded body; no error reflection."""

import http.client
import json
import sys


def execute(job):
    mode = job["mode"]
    if mode == "LIVE":
        connection = http.client.HTTPSConnection("ai-gateway.vercel.sh", 443, timeout=job["seconds"])
        headers = {"Authorization": "Bearer " + job["key"]}
    elif mode == "LOCAL_DOUBLE" and type(job["port"]) is int and 1 <= job["port"] <= 65535 and job["key"] is None:
        connection = http.client.HTTPConnection("127.0.0.1", job["port"], timeout=job["seconds"])
        headers = {}
    else:
        raise ValueError("invalid_transport_mode")
    limit = job["response_bytes"]
    if type(limit) is not int or not 1 <= limit <= 65536:
        raise ValueError("invalid_response_limit")
    headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    body = json.dumps(job["request"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode('utf-8')
    if len(body) > 98304:
        raise ValueError("request_byte_budget")
    try:
        connection.request("POST", "/v1/chat/completions", body, headers)
        response = connection.getresponse()
        data = response.read(limit + 1)
        if len(data) > limit:
            return {"error": "response_byte_budget"}
        if mode == "LIVE" and job["key"].encode('utf-8') in data:
            return {"error": "sensitive_response_blocked"}
        # HTTP error bodies never reach the host or its telemetry.
        return {"status": response.status, "body": data.decode('utf-8') if response.status == 200 else ""}
    finally:
        connection.close()


def main():
    try:
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072:
            raise ValueError("job_byte_budget")
        result = execute(json.loads(raw.decode('utf-8')))
    except Exception:
        result = {"error": "transport_failure"}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
