"""Read-only, manifest-bound GitHub Issues sandbox. No write operation exists."""

import math
import re
import threading
import time
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlsplit

from .contracts import ContractError, canonical, digest, strict_json, timestamp

API_VERSION = "2026-03-10"
ORIGIN = "https://api.github.com"
MARKER = "[STA-SANDBOX-20261011]"
LABEL = "security-triage-sandbox"
NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


class SandboxFailure(ValueError):
    """Only fixed codes and numeric rate metadata; never remote text or headers."""

    def __init__(self, code, *, status=None, retry_after=None, reset_at=None):
        super().__init__(code)
        self.code, self.status = code, status
        self.retry_after, self.reset_at = retry_after, reset_at


def positive(value):
    return type(value) is int and 1 <= value <= 2**63 - 1


def hexhash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


@dataclass(frozen=True)
class IssueBinding:
    number: int
    issue_id: int
    version: str
    fixture_sha256: str

    def __post_init__(self):
        if not positive(self.number) or not positive(self.issue_id) or not hexhash(self.version) or not hexhash(self.fixture_sha256):
            raise SandboxFailure("invalid_issue_binding")


@dataclass(frozen=True)
class SandboxConfig:
    owner: str
    repository: str
    repository_id: int
    account_id: int
    app_id: int
    installation_id: int
    issues: tuple
    mode: str = "INJECTED"
    max_requests: int = 20
    response_bytes: int = 65536
    deadline_seconds: float = 60

    def __post_init__(self):
        if (not isinstance(self.owner, str) or not NAME.fullmatch(self.owner)
                or not isinstance(self.repository, str) or not NAME.fullmatch(self.repository)
                or self.owner in {".", ".."} or self.repository in {".", ".."}
                or not all(positive(n) for n in (self.repository_id, self.account_id, self.app_id, self.installation_id))):
            raise SandboxFailure("invalid_repository_binding")
        if (type(self.issues) is not tuple or not 1 <= len(self.issues) <= 3
                or any(not isinstance(i, IssueBinding) for i in self.issues)
                or len({i.number for i in self.issues}) != len(self.issues)
                or len({i.issue_id for i in self.issues}) != len(self.issues)):
            raise SandboxFailure("invalid_issue_allowlist")
        if (self.mode not in {"INJECTED", "LOCAL_DOUBLE", "REAL_SANDBOX"}
                or type(self.max_requests) is not int or not 1 <= self.max_requests <= 20
                or type(self.response_bytes) is not int or not 1 <= self.response_bytes <= 65536
                or type(self.deadline_seconds) not in (int, float)
                or not math.isfinite(self.deadline_seconds) or not 0 < self.deadline_seconds <= 60):
            raise SandboxFailure("invalid_sandbox_limits")

    @property
    def repo_path(self):
        return f"/repos/{self.owner}/{self.repository}"

    @property
    def sha256(self):
        return digest(asdict(self))

    def allowed_paths(self):
        paths = {"/installation/repositories?per_page=2&page=1", self.repo_path}
        for issue in self.issues:
            base = f"{self.repo_path}/issues/{issue.number}"
            paths.add(base)
            paths.update(f"{base}/comments?per_page=50&page={page}" for page in (1, 2))
        return paths

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        try:
            data = dict(value)
            data["issues"] = tuple(IssueBinding(**item) for item in data["issues"])
            return cls(**data)
        except (TypeError, KeyError, ValueError):
            raise SandboxFailure("invalid_sandbox_config") from None


def text(value, limit=16384):
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
        raise SandboxFailure("schema_failure")
    return value


def record_projection(issue):
    """Canonical version recipe for a reviewed issue, not remote write approval."""
    try:
        if not isinstance(issue, dict) or "pull_request" in issue:
            raise SandboxFailure("issue_not_issue")
        if not positive(issue["id"]) or not positive(issue["number"]):
            raise SandboxFailure("schema_failure")
        if type(issue["comments"]) is not int or not 0 <= issue["comments"] <= 100:
            raise SandboxFailure("comment_count_limit")
        if issue["state"] not in {"open", "closed"}:
            raise SandboxFailure("schema_failure")
        timestamp(issue["updated_at"])
        labels = issue["labels"]
        if not isinstance(labels, list) or len(labels) > 20:
            raise SandboxFailure("schema_failure")
        names = [text(label["name"], 100) for label in labels]
        if len(set(names)) != len(names):
            raise SandboxFailure("schema_failure")
        return {"id": issue["id"], "number": issue["number"],
                "title": text(issue["title"], 1024), "body": text(issue["body"]),
                "state": issue["state"], "updated_at": issue["updated_at"],
                "comments": issue["comments"], "labels": sorted(names),
                "url": text(issue["url"], 512), "repository_url": text(issue["repository_url"], 512),
                "comments_url": text(issue["comments_url"], 512)}
    except (KeyError, TypeError, ContractError, UnicodeError):
        raise SandboxFailure("schema_failure") from None


def record_version(issue):
    return digest(record_projection(issue))


def rate_number(headers, name):
    value = headers.get(name)
    return int(value) if isinstance(value, str) and re.fullmatch(r"[0-9]{1,16}", value) else None


def next_page(link, path, current):
    """Validate pagination hints; callers build the next path themselves."""
    if not link:
        return None
    if not isinstance(link, str) or len(link) > 4096:
        raise SandboxFailure("pagination_schema")
    following, seen = None, set()
    for part in link.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="(next|prev|first|last)"\s*', part)
        if not match:
            raise SandboxFailure("pagination_schema")
        url, relation = match.groups()
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.path != path
                or parsed.fragment or len(query) != 2 or len(set(k for k, _ in query)) != 2
                or dict(query).get("per_page") != "50" or relation in seen):
            raise SandboxFailure("pagination_route")
        page_text = dict(query).get("page", "")
        if not re.fullmatch(r"[1-9][0-9]{0,5}", page_text):
            raise SandboxFailure("pagination_schema")
        page = int(page_text)
        if page > 2:
            raise SandboxFailure("pagination_limit")
        seen.add(relation)
        if relation == "next":
            if page != current + 1:
                raise SandboxFailure("pagination_route")
            following = page
    return following


class SandboxReader:
    """One sequential read session, at most20 requests/60 seconds, halts on failure."""

    def __init__(self, config, transport, *, monotonic=time.monotonic, cancelled=lambda: False):
        self.config, self.transport = config, transport
        self.clock, self.cancelled = monotonic, cancelled
        self.deadline = monotonic() + config.deadline_seconds
        self.requests = 0
        self.halted = False
        self.identity_checked = False
        self._active = threading.Lock()
        self.rate_stop = None

    def check(self):
        if self.cancelled():
            raise SandboxFailure("cancel_requested")
        if self.clock() >= self.deadline:
            raise SandboxFailure("deadline_exhausted")

    def get(self, path):
        try:
            if self.halted:
                raise SandboxFailure("session_halted")
            self.check()
            if self.rate_stop is not None:
                raise SandboxFailure("rate_limited", **self.rate_stop)
            if path not in self.config.allowed_paths():
                raise SandboxFailure("route_not_allowed")
            if self.requests >= self.config.max_requests:
                raise SandboxFailure("request_budget")
            self.requests += 1  # Reserve before dispatch, including failed requests.
            status, headers, body = self.transport.send(path, self.deadline, self.cancelled)
            self.check()
            if (type(status) is not int or not isinstance(headers, dict) or len(headers) > 16
                    or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 100 or len(v) > 4096 for k, v in headers.items())
                    or sum(len(k) + len(v) for k, v in headers.items()) > 8192):
                raise SandboxFailure("schema_failure")
            headers = {k.lower(): v for k, v in headers.items()}
            rate = {"status": status, "retry_after": rate_number(headers, "retry-after"),
                    "reset_at": rate_number(headers, "x-ratelimit-reset")}
            if status == 401:
                raise SandboxFailure("authentication_failed", **rate)
            if status == 429 or status == 403 and (rate["retry_after"] is not None or headers.get("x-ratelimit-remaining") == "0"):
                raise SandboxFailure("rate_limited", **rate)
            if status == 403:
                raise SandboxFailure("forbidden", **rate)
            if status == 404:
                raise SandboxFailure("not_found", **rate)
            if 300 <= status < 400:
                raise SandboxFailure("redirect_rejected", status=status)
            if 500 <= status <= 599:
                raise SandboxFailure("service_failure", status=status)
            if status != 200:
                raise SandboxFailure("unexpected_status", status=status)
            if headers.get("x-ratelimit-remaining") == "0" or rate["retry_after"] is not None:
                self.rate_stop = rate  # Even200 may exhaust the primary quota.
            if headers.get("x-github-api-version-selected", API_VERSION) != API_VERSION:
                raise SandboxFailure("api_version_mismatch")
            if headers.get("content-type", "").split(";")[0].strip() not in {"application/json", "application/vnd.github+json"}:
                raise SandboxFailure("schema_failure")
            if not isinstance(body, str) or len(body.encode("utf-8")) > self.config.response_bytes:
                raise SandboxFailure("response_byte_budget")
            return strict_json(body), headers
        except SandboxFailure:
            self.halted = True
            raise
        except OSError:
            self.halted = True
            raise SandboxFailure("transport_response_lost") from None
        except (ContractError, ValueError, TypeError, UnicodeError):
            self.halted = True
            raise SandboxFailure("schema_failure") from None

    def repository(self, data):
        try:
            if (not isinstance(data, dict) or type(data["id"]) is not int or data["id"] != self.config.repository_id
                    or type(data["owner"]["id"]) is not int or data["owner"]["id"] != self.config.account_id
                    or data["owner"]["login"] != self.config.owner
                    or data["full_name"] != f"{self.config.owner}/{self.config.repository}"
                    or data["url"] != ORIGIN + self.config.repo_path):
                raise SandboxFailure("repository_identity_mismatch")
        except (KeyError, TypeError):
            raise SandboxFailure("schema_failure") from None

    def identity(self):
        data, headers = self.get("/installation/repositories?per_page=2&page=1")
        if (not isinstance(data, dict) or type(data.get("total_count")) is not int or data["total_count"] != 1
                or not isinstance(data.get("repositories"), list) or len(data["repositories"]) != 1 or headers.get("link")):
            raise SandboxFailure("token_repository_scope_mismatch")
        self.repository(data["repositories"][0])
        repo, _ = self.get(self.config.repo_path)
        self.repository(repo)
        self.identity_checked = True

    def issue(self, binding):
        path = f"{self.config.repo_path}/issues/{binding.number}"
        data, _ = self.get(path)
        value = record_projection(data)
        if (value["id"] != binding.issue_id or value["number"] != binding.number
                or value["url"] != ORIGIN + path or value["repository_url"] != ORIGIN + self.config.repo_path
                or value["comments_url"] != ORIGIN + path + "/comments"):
            raise SandboxFailure("issue_identity_mismatch")
        if (not value["title"].startswith(MARKER + " ") or LABEL not in value["labels"]
                or f"[STA-FIXTURE-SHA256:{binding.fixture_sha256}]" not in value["body"]):
            raise SandboxFailure("synthetic_marker_mismatch")
        if digest(value) != binding.version:
            raise SandboxFailure("stale_issue_version")
        return value

    def read_case(self, number):
        if not self._active.acquire(blocking=False):
            raise SandboxFailure("concurrent_read_rejected")
        try:
            return self._read_case(number)
        finally:
            self._active.release()

    def _read_case(self, number):
        try:
            if self.halted:
                raise SandboxFailure("session_halted")
            binding = next((i for i in self.config.issues if type(number) is int and i.number == number), None)
            if binding is None:
                raise SandboxFailure("issue_not_allowlisted")
            if not self.identity_checked:
                self.identity()
            issue = self.issue(binding)
            path = f"{self.config.repo_path}/issues/{number}/comments"
            comments, page = [], 1
            while page is not None:
                rows, headers = self.get(f"{path}?per_page=50&page={page}")
                if not isinstance(rows, list) or len(rows) > 50:
                    raise SandboxFailure("comment_schema")
                for row in rows:
                    if (not isinstance(row, dict) or not positive(row.get("id"))
                            or row.get("issue_url") != issue["url"] or not isinstance(row.get("user"), dict)
                            or not positive(row["user"].get("id"))):
                        raise SandboxFailure("comment_identity_mismatch")
                    cid = row["id"]
                    if row.get("url") != ORIGIN + self.config.repo_path + f"/issues/comments/{cid}":
                        raise SandboxFailure("comment_identity_mismatch")
                    timestamp(row["updated_at"])
                    comments.append({"id": cid, "body": text(row["body"]), "updated_at": row["updated_at"],
                                     "user_id": row["user"]["id"], "user_login": text(row["user"]["login"], 100)})
                page = next_page(headers.get("link"), path, page)
            if len({c["id"] for c in comments}) != len(comments) or len(comments) != issue["comments"]:
                raise SandboxFailure("incomplete_or_duplicate_comments")
            self.issue(binding)  # Bookend the comments with the same approved issue version.
            snapshot = {"mode": self.config.mode, "repository_id": self.config.repository_id,
                        "account_id": self.config.account_id, "issue": issue, "comments": comments,
                        "record_version": binding.version, "config_sha256": self.config.sha256}
            if len(canonical(snapshot).encode("utf-8")) > 131072:
                raise SandboxFailure("snapshot_byte_budget")
            return {**snapshot, "snapshot_sha256": digest(snapshot), "requests": self.requests,
                    "writes": 0, "containment": "NOT_IMPLEMENTED"}
        except SandboxFailure:
            self.halted = True
            raise
        except (KeyError, TypeError, ValueError, ContractError, UnicodeError):
            self.halted = True
            raise SandboxFailure("schema_failure") from None
