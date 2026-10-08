"""Immutable input snapshots and host-owned transactional workflow records."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .contracts import (ContractError, POLICY_VERSION, PROMPT_VERSION, canonical,
                        digest, identifier, keys, positive_integer, timestamp)

KINDS = {
    "identity": {"user_id", "privileged"},
    "device": {"user_id", "device_id", "managed"},
    "network": {"user_id", "ip", "approved", "valid_from", "valid_to"},
    "travel": {"user_id", "ip", "approved", "valid_from", "valid_to"},
    "auth": {"user_id", "session_id", "device_id", "ip", "outcome", "mfa"},
    "resource": {"user_id", "session_id", "sensitive"},
    "coverage": {"user_id", "stream", "complete", "gap", "from", "to"},
}


def validate_snapshot(snapshot):
    keys(snapshot, ("schema_version", "fictional", "case_id", "snapshot_version",
                    "window_start", "cutoff", "alert", "records"))
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise ContractError("unsupported_schema")
    if snapshot["fictional"] is not True:
        raise ContractError("fictional_inputs_only")
    identifier(snapshot["case_id"])
    positive_integer(snapshot["snapshot_version"])
    start, cutoff = timestamp(snapshot["window_start"]), timestamp(snapshot["cutoff"])
    if not 0 < (cutoff - start).total_seconds() <= 7 * 86400:
        raise ContractError("invalid_case_window")
    alert = snapshot["alert"]
    keys(alert, ("user_id", "device_id", "ip", "session_id", "priority"))
    for name in ("user_id", "device_id", "session_id"):
        identifier(alert[name])
    if alert["priority"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ContractError("invalid_alert_priority")
    if not isinstance(alert["ip"], str) or len(alert["ip"]) > 64:
        raise ContractError("invalid_ip")
    if not isinstance(snapshot["records"], list) or len(snapshot["records"]) > 500:
        raise ContractError("invalid_record_count")
    seen = set()
    for record in snapshot["records"]:
        keys(record, ("id", "kind", "version", "event_time", "ingested_at", "data"))
        identifier(record["id"])
        if record["id"] in seen:
            raise ContractError("duplicate_record_id")
        seen.add(record["id"])
        positive_integer(record["version"])
        timestamp(record["event_time"])
        timestamp(record["ingested_at"])
        kind = record["kind"]
        if not isinstance(kind, str) or kind not in KINDS:
            raise ContractError("unknown_record_kind")
        keys(record["data"], KINDS[kind])
        data = record["data"]
        if data["user_id"] != alert["user_id"]:
            raise ContractError("cross_case_subject")
        for name in ("session_id", "device_id"):
            if name in data:
                identifier(data[name])
        if "ip" in data and (not isinstance(data["ip"], str) or len(data["ip"]) > 64):
            raise ContractError("invalid_ip")
        for name in ("privileged", "managed", "approved", "sensitive", "complete"):
            if name in data and type(data[name]) is not bool:
                raise ContractError("boolean_required")
        if kind == "auth" and (data["outcome"] not in ("success", "failure") or
                               data["mfa"] not in ("denied", "satisfied", "unknown")):
            raise ContractError("invalid_auth_fields")
        if kind in ("network", "travel") and timestamp(data["valid_from"]) > timestamp(data["valid_to"]):
            raise ContractError("invalid_network_interval")
        if kind == "coverage":
            if data["stream"] not in ("auth", "resource"):
                raise ContractError("invalid_coverage_stream")
            if timestamp(data["from"]) > timestamp(data["to"]):
                raise ContractError("invalid_coverage_interval")
            if not isinstance(data["gap"], str) or len(data["gap"]) > 240:
                raise ContractError("invalid_gap")
            if data["complete"] == bool(data["gap"]):
                raise ContractError("inconsistent_coverage")
        if len(canonical(record).encode("utf-8")) > 4096:
            raise ContractError("oversized_record")
    identities = [r for r in snapshot["records"] if r["kind"] == "identity"]
    if len(identities) != 1:
        raise ContractError("exactly_one_identity_required")


def create_evidence(path: Path, snapshots: list[dict]):
    """Create once. Existing content must match; never overwrite evidence."""
    for snapshot in snapshots:
        validate_snapshot(snapshot)
    if len({s["case_id"] for s in snapshots}) != len(snapshots):
        raise ContractError("duplicate_case_id")
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            saved = {row[0]: row[1] for row in db.execute("SELECT case_id, digest FROM cases")}
        if saved != {s["case_id"]: digest(s) for s in snapshots}:
            raise ContractError("existing_output_conflict")
        return
    with closing(sqlite3.connect(path)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            PRAGMA user_version=1;
            CREATE TABLE cases(case_id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                               input_json TEXT NOT NULL);
            CREATE TABLE records(case_id TEXT NOT NULL, record_id TEXT NOT NULL,
                                 kind TEXT NOT NULL, record_json TEXT NOT NULL,
                                 PRIMARY KEY(case_id, record_id),
                                 FOREIGN KEY(case_id) REFERENCES cases(case_id));
        """)
        for snapshot in snapshots:
            db.execute("INSERT INTO cases VALUES(?,?,?)",
                       (snapshot["case_id"], digest(snapshot), canonical(snapshot)))
            db.executemany("INSERT INTO records VALUES(?,?,?,?)", [
                (snapshot["case_id"], r["id"], r["kind"], canonical(r))
                for r in snapshot["records"]])
        db.commit()


class EvidenceStore:
    def __init__(self, path, case_id):
        self.db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
        self.db.execute("PRAGMA query_only=ON")
        if self.db.execute("PRAGMA user_version").fetchone()[0] != 1:
            self.close()
            raise ContractError("unsupported_database_schema")
        row = self.db.execute("SELECT input_json, digest FROM cases WHERE case_id=?",
                              (case_id,)).fetchone()
        if row is None:
            self.close()
            raise ContractError("unknown_case")
        self.snapshot, self.snapshot_digest = json.loads(row[0]), row[1]
        self.case_id = case_id
        indexed = self.db.execute(
            "SELECT record_id,kind,record_json FROM records WHERE case_id=? ORDER BY record_id", (case_id,)).fetchall()
        records = [json.loads(r[2]) for r in indexed]
        if (digest(self.snapshot) != self.snapshot_digest
                or records != sorted(self.snapshot["records"], key=lambda r: r["id"])
                or any(rid != r["id"] or kind != r["kind"] for (rid, kind, _), r in zip(indexed, records))):
            self.close()
            raise ContractError("evidence_integrity_failure")

    def records(self, kind):
        rows = self.db.execute(
            "SELECT record_json FROM records WHERE case_id=? AND kind=? ORDER BY record_id",
            (self.case_id, kind)).fetchall()
        cutoff = timestamp(self.snapshot["cutoff"])
        start = timestamp(self.snapshot["window_start"])
        records = [json.loads(row[0]) for row in rows]
        return sorted([r for r in records if timestamp(r["ingested_at"]) <= cutoff
                       and timestamp(r["event_time"]) <= cutoff
                       and (kind not in ("auth", "resource") or
                            timestamp(r["event_time"]) >= start)],
                      key=lambda r: (r["event_time"], r["id"]))

    def close(self):
        self.db.close()


from .workflow import RunStore  # Public compatibility import; schema 2 uses a fresh output.
