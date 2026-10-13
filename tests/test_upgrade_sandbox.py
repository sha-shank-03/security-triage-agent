"""Pure injected sandbox contracts. No sockets, child processes or credentials."""

import copy
import json
import socket
import subprocess
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from security_triage.contracts import digest
from security_triage.sandbox import (API_VERSION, LABEL, MARKER, ORIGIN, IssueBinding,
    SandboxConfig, SandboxFailure, SandboxReader, next_page, record_version)
from security_triage.sandbox_transport import RuntimeCredential, SandboxChildTransport
from security_triage.sandbox_worker import execute


def sample(mode="INJECTED", *, max_requests=20, deadline=60):
    path = "/repos/synthetic-owner/synthetic-cases"
    repository = {"id": 101, "full_name": "synthetic-owner/synthetic-cases",
                  "owner": {"id": 102, "login": "synthetic-owner"}, "url": ORIGIN + path}
    issue = {"id": 201, "number": 3, "title": MARKER + " synthetic case",
             "body": "Fictional evidence only. [STA-FIXTURE-SHA256:" + "a" * 64 + "]",
             "labels": [{"name": LABEL}], "state": "open", "comments": 1,
             "updated_at": "2026-10-12T06:00:00Z", "url": ORIGIN + path + "/issues/3",
             "repository_url": ORIGIN + path, "comments_url": ORIGIN + path + "/issues/3/comments"}
    comment = {"id": 301, "body": "Synthetic existing note", "updated_at": "2026-10-12T06:00:00Z",
               "issue_url": issue["url"], "url": ORIGIN + path + "/issues/comments/301",
               "user": {"id": 401, "login": "synthetic-app[bot]"}}
    binding = IssueBinding(3, 201, record_version(issue), "a" * 64)
    config = SandboxConfig("synthetic-owner", "synthetic-cases", 101, 102, 103, 104, (binding,),
                           mode=mode, max_requests=max_requests, deadline_seconds=deadline)
    return config, repository, issue, comment


def response(value, status=200, headers=None):
    return status, {"content-type": "application/json", **(headers or {})}, json.dumps(value)


class Injected:
    def __init__(self, rows):
        self.rows, self.paths = list(rows), []

    def send(self, path, deadline, cancelled):
        self.paths.append(path)
        value = self.rows.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def session(*, mode="INJECTED", issue_mutation=None, final_mutation=None, comment_mutation=None,
            max_requests=20, clock=lambda: 0, cancelled=lambda: False):
    config, repo, issue, comment = sample(mode, max_requests=max_requests)
    first, final = copy.deepcopy(issue), copy.deepcopy(issue)
    if issue_mutation:
        issue_mutation(first)
    if final_mutation:
        final_mutation(final)
    if comment_mutation:
        comment_mutation(comment)
    transport = Injected([response({"total_count": 1, "repositories": [repo]}), response(repo),
                          response(first), response([comment]), response(final)])
    return SandboxReader(config, transport, monotonic=clock, cancelled=cancelled), transport


class SandboxPure(unittest.TestCase):
    def setUp(self):
        self.network = patch.object(socket, "create_connection", side_effect=AssertionError("pure test opened socket"))
        self.children = patch.object(subprocess, "Popen", side_effect=AssertionError("pure test spawned child"))
        self.network.start()
        self.children.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.children.stop)

    def failure(self, code, function):
        with self.assertRaises(SandboxFailure) as caught:
            function()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_complete_snapshot_has_bound_identity_version_and_no_effect(self):
        reader, transport = session()
        value = reader.read_case(3)
        self.assertEqual(value["record_version"], reader.config.issues[0].version)
        self.assertEqual(value["repository_id"], 101)
        self.assertEqual(value["issue"]["id"], 201)
        self.assertEqual(value["comments"][0]["user_id"], 401)
        snapshot = {k: v for k, v in value.items() if k not in {"snapshot_sha256", "requests", "writes", "containment"}}
        self.assertEqual(value["snapshot_sha256"], digest(snapshot))
        self.assertEqual(value["requests"], 5)
        self.assertEqual(value["writes"], 0)
        self.assertEqual(value["containment"], "NOT_IMPLEMENTED")
        self.assertTrue(all(p in reader.config.allowed_paths() for p in transport.paths))
        self.assertEqual(transport.paths[-1], transport.paths[2])

    def test_configuration_rejects_path_injection_boolean_ids_and_unbounded_limits(self):
        config, *_ = sample()
        for delta in ({"owner": "bad/owner"}, {"repository": ".."}, {"repository_id": True},
                      {"max_requests": 21}, {"response_bytes": 65537}, {"deadline_seconds": float("nan")},
                      {"issues": (config.issues[0], config.issues[0])}):
            with self.subTest(delta=delta), self.assertRaises(SandboxFailure):
                replace(config, **delta)
        self.assertEqual(SandboxConfig.from_dict(config.to_dict()), config)

    def test_unapproved_number_and_route_stop_before_transport(self):
        reader, transport = session()
        self.failure("issue_not_allowlisted", lambda: reader.read_case(999))
        self.assertEqual(transport.paths, [])
        reader, transport = session()
        self.failure("route_not_allowed", lambda: reader.get("https://evil.invalid/"))
        self.assertEqual(transport.paths, [])

    def test_token_repository_scope_and_account_identity_must_match(self):
        for mutation in (lambda d: d.update(total_count=2),
                         lambda d: d["repositories"][0].update(id=999),
                         lambda d: d["repositories"][0]["owner"].update(id=999)):
            reader, transport = session()
            data = json.loads(transport.rows[0][2]); mutation(data); transport.rows[0] = response(data)
            with self.assertRaises(SandboxFailure):
                reader.read_case(3)
            self.assertEqual(len(transport.paths), 1)
            self.failure("session_halted", lambda: reader.read_case(3))

    def test_issue_id_number_and_pr_shape_are_rejected(self):
        for field, value, expected in [("id", 999, "issue_identity_mismatch"),
                                      ("number", 4, "issue_identity_mismatch"),
                                      ("pull_request", {}, "issue_not_issue")]:
            reader, _ = session(issue_mutation=lambda d: d.update({field: value}))
            self.failure(expected, lambda: reader.read_case(3))

    def test_marker_label_fixture_hash_and_version_are_bound(self):
        for field, value, expected in [("title", "unmarked", "synthetic_marker_mismatch"),
            ("labels", [], "synthetic_marker_mismatch"), ("body", "foreign fixture", "synthetic_marker_mismatch"),
            ("updated_at", "2026-10-12T06:00:01Z", "stale_issue_version"),
            ("state", "closed", "stale_issue_version")]:
            reader, _ = session(issue_mutation=lambda d: d.update({field: value}))
            self.failure(expected, lambda: reader.read_case(3))

    def test_comment_cross_issue_duplicate_and_incomplete_reads_fail(self):
        reader, _ = session(comment_mutation=lambda d: d.update(issue_url=ORIGIN + "/foreign"))
        self.failure("comment_identity_mismatch", lambda: reader.read_case(3))
        for rows in ([], [sample()[3], sample()[3]]):
            reader, transport = session(); transport.rows[3] = response(rows)
            self.failure("incomplete_or_duplicate_comments", lambda: reader.read_case(3))

    def test_issue_drift_during_comment_read_halts_snapshot(self):
        reader, transport = session(final_mutation=lambda d: d.update(updated_at="2026-10-12T06:01:00Z"))
        self.failure("stale_issue_version", lambda: reader.read_case(3))
        self.assertEqual(len(transport.paths), 5)

    def test_additive_remote_fields_do_not_rebind_record_version(self):
        reader, _ = session(issue_mutation=lambda d: d.update(future_optional_field={"anything": True}))
        self.assertEqual(reader.read_case(3)["record_version"], reader.config.issues[0].version)

    def test_two_comment_pages_are_constructed_and_complete(self):
        config, repo, issue, comment = sample(); issue["comments"] = 2
        config = replace(config, issues=(replace(config.issues[0], version=record_version(issue)),))
        other = copy.deepcopy(comment); other.update(id=302, url=ORIGIN + config.repo_path + "/issues/comments/302")
        link = '<' + issue["comments_url"] + '?per_page=50&page=2>; rel="next"'
        transport = Injected([response({"total_count": 1, "repositories": [repo]}), response(repo), response(issue),
                              response([comment], headers={"link": link}), response([other]), response(issue)])
        value = SandboxReader(config, transport, monotonic=lambda: 0).read_case(3)
        self.assertEqual(len(value["comments"]), 2)
        self.assertEqual(transport.paths[4], config.repo_path + "/issues/3/comments?per_page=50&page=2")

    def test_hostile_next_url_and_third_page_never_dispatch(self):
        path = sample()[0].repo_path + "/issues/3/comments"
        for url, expected in [("https://evil.invalid" + path + "?per_page=50&page=2", "pagination_route"),
                              (ORIGIN + path + "?per_page=50&page=3", "pagination_limit"),
                              (ORIGIN + path + "?per_page=50&page=2&token=bad", "pagination_route")]:
            reader, transport = session(); transport.rows[3] = response([sample()[3]], headers={"link": '<' + url + '>; rel="next"'})
            self.failure(expected, lambda: reader.read_case(3))
            self.assertEqual(len(transport.paths), 4)
        self.failure("pagination_schema", lambda: next_page("broken", path, 1))

    def test_http_errors_are_typed_redacted_once_and_never_replayed(self):
        for status, code in [(401, "authentication_failed"), (403, "forbidden"), (404, "not_found"),
                             (429, "rate_limited"), (500, "service_failure"), (503, "service_failure"), (301, "redirect_rejected")]:
            reader, transport = session(); transport.rows[0] = response("SYNTHETIC_SECRET_SENTINEL", status)
            error = self.failure(code, lambda: reader.read_case(3))
            self.assertNotIn("SYNTHETIC_SECRET_SENTINEL", str(error))
            self.failure("session_halted", lambda: reader.read_case(3))
            self.assertEqual(len(transport.paths), 1)

    def test_rate_metadata_preserves_full_delay_without_sleep_or_retry(self):
        reader, transport = session()
        transport.rows[0] = response({}, 403, {"retry-after": "120", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791790000"})
        error = self.failure("rate_limited", lambda: reader.read_case(3))
        self.assertEqual((error.retry_after, error.reset_at), (120, 1791790000))
        self.assertEqual(len(transport.paths), 1)

    def test_success_with_exhausted_quota_blocks_next_reserved_request(self):
        reader, transport = session()
        data = json.loads(transport.rows[0][2])
        transport.rows[0] = response(data, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791790000"})
        error = self.failure("rate_limited", lambda: reader.read_case(3))
        self.assertEqual((error.status, error.reset_at), (200, 1791790000))
        self.assertEqual((reader.requests, len(transport.paths)), (1, 1))

    def test_schema_duplicate_keys_body_limit_and_api_version_fail_closed(self):
        for row, code in [(response({"wrong": True}), "token_repository_scope_mismatch"),
            ((200, {"content-type": "application/json"}, '{"id":1,"id":2}'), "schema_failure"),
            ((200, {"content-type": "application/json"}, " " * 65537), "response_byte_budget"),
            (response({}, headers={"content-type": "text/html"}), "schema_failure"),
            (response({}, headers={"x-github-api-version-selected": "2022-11-28"}), "api_version_mismatch")]:
            reader, transport = session(); transport.rows[0] = row
            self.failure(code, lambda: reader.read_case(3))

    def test_cancellation_deadline_and_request_reservation(self):
        reader, transport = session(cancelled=lambda: True)
        self.failure("cancel_requested", lambda: reader.read_case(3)); self.assertEqual(transport.paths, [])
        clock = Mock(side_effect=[0, 60])
        reader, transport = session(clock=clock)
        self.failure("deadline_exhausted", lambda: reader.read_case(3)); self.assertEqual(transport.paths, [])
        reader, transport = session(max_requests=3)
        self.failure("request_budget", lambda: reader.read_case(3))
        self.assertEqual((reader.requests, len(transport.paths)), (3, 3))
        reader, transport = session(); transport.rows[0] = OSError("private remote detail")
        self.failure("transport_response_lost", lambda: reader.read_case(3))
        self.assertEqual(reader.requests, 1)

    def test_deadline_and_cancel_are_rechecked_after_injected_response(self):
        for clock, cancelled, code in [(Mock(side_effect=[0, 0, 61]), lambda: False, "deadline_exhausted"),
                                      (lambda: 0, Mock(side_effect=[False, True]), "cancel_requested")]:
            reader, transport = session(clock=clock, cancelled=cancelled)
            self.failure(code, lambda: reader.read_case(3)); self.assertEqual(len(transport.paths), 1)

    def test_concurrent_reader_and_transport_are_rejected_without_dispatch(self):
        reader, transport = session()
        reader._active.acquire()
        try:
            self.failure("concurrent_read_rejected", lambda: reader.read_case(3))
        finally:
            reader._active.release()
        self.assertEqual(transport.paths, [])
        config, *_ = sample("LOCAL_DOUBLE")
        child = SandboxChildTransport(config, local_port=12345)
        child._active.acquire()
        try:
            self.failure("concurrent_transport_rejected", lambda: child.send(config.repo_path, 1, lambda: False))
        finally:
            child._active.release()

    def credential(self, config):
        return RuntimeCredential("SYNTHETIC_TOKEN_SENTINEL", 103, 104, 102, (101,),
                                 (("issues", "read"), ("metadata", "read")), "2026-10-12T07:00:00Z",
                                 config.sha256, "synthetic-main-dispatch")

    def test_trusted_token_attestation_binds_ids_scope_expiry_and_configuration(self):
        config, *_ = sample("REAL_SANDBOX"); credential = self.credential(config)
        now = datetime(2026, 10, 12, 6, 30, tzinfo=timezone.utc)
        credential.check(config, now)
        self.assertNotIn("SYNTHETIC_TOKEN_SENTINEL", repr(credential))
        for delta in ({"account_id": 999}, {"installation_id": 999}, {"app_id": 999},
                      {"repository_ids": (101, 999)}, {"permissions": (("issues", "write"), ("metadata", "read"))},
                      {"expires_at": "2026-10-12T06:00:00Z"}, {"config_sha256": "f" * 64}):
            self.failure("runtime_identity_or_authority_mismatch", lambda: replace(credential, **delta).check(config, now))
        self.failure("trusted_runtime_credential_required", lambda: SandboxChildTransport(config))

    def worker(self, *, status=200, body=b"{}", headers=None, mode="LOCAL_DOUBLE"):
        config, *_ = sample(mode)
        remote = Mock(); remote.status = status
        remote.read.return_value = body; remote.getheaders.return_value = headers or [("Content-Type", "application/json")]
        connection = Mock(); connection.getresponse.return_value = remote
        job = {"config": config.to_dict(), "path": config.repo_path, "seconds": 1,
               "port": 12345 if mode == "LOCAL_DOUBLE" else None,
               "token": "SYNTHETIC_TOKEN_SENTINEL" if mode == "REAL_SANDBOX" else None}
        return config, remote, connection, job

    def test_worker_uses_fixed_https_get_version_and_no_write_body(self):
        config, remote, connection, job = self.worker(mode="REAL_SANDBOX")
        with patch("security_triage.sandbox_worker.http.client.HTTPSConnection", return_value=connection) as factory:
            result = execute(job)
        factory.assert_called_once_with("api.github.com", 443, timeout=1)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("GET", config.repo_path))
        self.assertNotIn("body", kwargs)
        self.assertEqual(kwargs["headers"]["X-GitHub-Api-Version"], API_VERSION)
        self.assertEqual(result["status"], 200)
        connection.close.assert_called_once()
        job["path"] = "/repos/foreign/writes"
        with self.assertRaises(ValueError):
            execute(job)

    def test_worker_drops_errors_caps_body_and_blocks_reflected_synthetic_secret(self):
        for status, body, mode, expected in [(403, b"private error", "LOCAL_DOUBLE", None),
                (200, b"x" * 65537, "LOCAL_DOUBLE", "response_byte_budget"),
                (200, b"SYNTHETIC_TOKEN_SENTINEL", "REAL_SANDBOX", "sensitive_response_blocked")]:
            _, remote, connection, job = self.worker(status=status, body=body, mode=mode)
            with patch("security_triage.sandbox_worker.http.client.HTTPConnection", return_value=connection), patch("security_triage.sandbox_worker.http.client.HTTPSConnection", return_value=connection):
                result = execute(job)
            if expected:
                self.assertEqual(result, {"error": expected})
            else:
                self.assertEqual(result["body"], ""); remote.read.assert_not_called()
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
