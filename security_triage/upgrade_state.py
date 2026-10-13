"""Small durable U1 ledger; reservations and expiry never reset on resume."""

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from .contracts import ContractError, canonical, digest, timestamp
from .gateway import VERSION
from .upgrade_events import redact


def utc_now():
    return datetime.now(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class UpgradeState:
    def __init__(self, path, *, clock=utc_now, monotonic=time.monotonic, secrets=()):
        self.clock, self.monotonic, self.secrets = clock, monotonic, secrets
        self.db = sqlite3.connect(path, timeout=1)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        if self.db.execute("PRAGMA user_version").fetchone()[0] not in (0, 101):
            raise ContractError("upgrade_schema_mismatch")
        self.db.executescript("""
          PRAGMA user_version=101;
          CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, source_json TEXT NOT NULL,
            config_json TEXT NOT NULL, versions_json TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, last_at TEXT NOT NULL, elapsed REAL NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, corrections INTEGER NOT NULL DEFAULT 0,
            reserved INTEGER NOT NULL DEFAULT 0, cancelled INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'INVESTIGATING');
          CREATE TABLE IF NOT EXISTS attempts(run_id TEXT REFERENCES runs(run_id), seq INTEGER,
            request_json TEXT NOT NULL, packet_json TEXT, call_json TEXT, observation_json TEXT,
            reason TEXT NOT NULL DEFAULT 'REQUEST_STARTED', reservation INTEGER NOT NULL,
            PRIMARY KEY(run_id,seq));
          CREATE TABLE IF NOT EXISTS outcomes(run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
            raw_json TEXT, guarded_json TEXT NOT NULL, reason TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(event_id INTEGER PRIMARY KEY, run_id TEXT REFERENCES runs(run_id),
            kind TEXT NOT NULL, data_json TEXT NOT NULL, at TEXT NOT NULL);
        """)
        self.run_id = None
        self.started = None
        self.previous_elapsed = 0.0

    def event(self, kind, data):
        self.db.execute("INSERT INTO events(run_id,kind,data_json,at) VALUES(?,?,?,?)",
                        (self.run_id, kind, canonical(redact(data, self.secrets)), iso(self.clock())))

    def row(self):
        return dict(self.db.execute("SELECT * FROM runs WHERE run_id=?", (self.run_id,)).fetchone())

    def start(self, source, config, versions, *, request_id="default", resume=False):
        config.authorize(self.clock())
        self.run_id = digest({"source": source, "config": config.public(), "versions": versions, "request_id": request_id})[:24]
        row = self.db.execute("SELECT * FROM runs WHERE run_id=?", (self.run_id,)).fetchone()
        if row is None:
            if resume or self.db.execute("SELECT count(*) FROM runs").fetchone()[0]:
                raise ContractError("resume_identity_mismatch_or_output_used")
            now = self.clock()
            with self.db:
                self.db.execute("INSERT INTO runs(run_id,source_json,config_json,versions_json,created_at,expires_at,last_at) VALUES(?,?,?,?,?,?,?)",
                    (self.run_id, canonical(source), canonical(config.public()), canonical(versions), iso(now), iso(now + timedelta(seconds=config.deadline_seconds)), iso(now)))
                self.event("run_started", {"mode": config.mode, "version": VERSION, "config_sha256": digest(config.public()), "dataset_sha256": digest(source), "automatic_transport_retries": 0})
        else:
            if not resume and row["state"] == "INVESTIGATING":
                raise ContractError("explicit_resume_required")
            if row["config_json"] != canonical(config.public()) or row["versions_json"] != canonical(versions):
                raise ContractError("resume_configuration_mismatch")
        row = self.row()
        self.previous_elapsed = row["elapsed"]
        self.started = self.monotonic()
        wall_remaining = (timestamp(row["expires_at"]) - self.clock()).total_seconds()
        self.deadline = self.started + max(0, min(wall_remaining, config.deadline_seconds - row["elapsed"]))
        if self.clock() < timestamp(row["last_at"]):
            raise ContractError("wall_clock_rollback")
        self.config = config
        return self.run_id

    def check_active(self):
        row = self.row()
        if row["state"] != "INVESTIGATING":
            raise ContractError("run_not_active")
        if row["cancelled"]:
            raise ContractError("cancel_requested")
        if self.monotonic() >= self.deadline or self.clock() >= timestamp(row["expires_at"]) or self.clock() < timestamp(row["last_at"]):
            raise ContractError("deadline_exhausted")
        self.config.authorize(self.clock())

    def checkpoint(self):
        elapsed = self.previous_elapsed + max(0, self.monotonic() - self.started)
        self.db.execute("UPDATE runs SET elapsed=?,last_at=? WHERE run_id=?", (elapsed, iso(self.clock()), self.run_id))

    def reserve(self, request):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.check_active()
            row = self.row()
            if row["attempts"] >= self.config.max_attempts:
                raise ContractError("attempt_budget_exhausted")
            if row["corrections"] > self.config.max_corrections:
                raise ContractError("correction_budget_exhausted")
            if self.db.execute("SELECT 1 FROM attempts WHERE run_id=? AND reason='REQUEST_STARTED'", (self.run_id,)).fetchone():
                raise ContractError("ambiguous_inflight_attempt")
            amount = self.config.attempt_reservation_minor_units
            if row["reserved"] + amount > self.config.allocation_minor_units:
                raise ContractError("allocation_exhausted")
            seq = row["attempts"] + 1
            self.db.execute("UPDATE runs SET attempts=?,reserved=reserved+? WHERE run_id=?", (seq, amount, self.run_id))
            self.db.execute("INSERT INTO attempts(run_id,seq,request_json,reservation) VALUES(?,?,?,?)", (self.run_id, seq, canonical(redact(request, self.secrets)), amount))
            self.checkpoint()
            self.event("attempt_reserved", {"seq": seq, "reservation_minor_units": amount, "estimated_cost": None, "actual_cost": None})
        return seq

    def record_packet(self, seq, packet):
        with self.db:
            changed = self.db.execute("UPDATE attempts SET packet_json=? WHERE run_id=? AND seq=? AND reason='REQUEST_STARTED' AND packet_json IS NULL",
                (canonical(redact(packet, self.secrets)), self.run_id, seq))
            if changed.rowcount != 1:
                raise ContractError("packet_not_reserved_or_replayed")
            self.event("raw_packet_recorded", {"seq": seq, "generation_id": packet.get("id"), "model_returned": packet.get("model"), "provider_returned": packet.get("provider"), "usage": packet.get("usage"), "actual_cost": None})

    def record_call(self, seq, call):
        with self.db:
            self.db.execute("UPDATE attempts SET call_json=? WHERE run_id=? AND seq=?", (canonical(redact(call, self.secrets)), self.run_id, seq))
            if call["tool"] == "finish_investigation":
                self.event("raw_recommendation_recorded", {"seq": seq, "raw_recommendation": call["arguments"]})

    def resolve(self, seq, reason, observation=None, *, correction=False):
        with self.db:
            changed = self.db.execute("UPDATE attempts SET reason=?,observation_json=? WHERE run_id=? AND seq=? AND reason='REQUEST_STARTED'",
                (reason, canonical(observation) if observation is not None else None, self.run_id, seq))
            if changed.rowcount != 1:
                raise ContractError("attempt_not_reserved_or_replayed")
            self.db.execute("UPDATE runs SET corrections=corrections+? WHERE run_id=?", (int(correction), self.run_id))
            self.checkpoint()
            self.event("attempt_resolved", {"seq": seq, "reason": reason, "correction": correction, "actual_cost": None})

    def request_cancel(self):
        with self.db:
            self.db.execute("UPDATE runs SET cancelled=1 WHERE run_id=? AND state='INVESTIGATING'", (self.run_id,))
            self.event("cancel_requested", {})

    def finish(self, raw, guarded, reason, *, seq=None):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.row()["state"] != "INVESTIGATING":
                raise ContractError("run_not_active")
            if reason == "validated_finish":
                self.check_active()
            if self.row()["cancelled"] and reason != "cancel_requested":
                raise ContractError("cancel_requested")
            if seq is not None:
                changed = self.db.execute("UPDATE attempts SET reason=? WHERE run_id=? AND seq=? AND reason='REQUEST_STARTED'", (reason, self.run_id, seq))
                if changed.rowcount != 1:
                    raise ContractError("attempt_not_reserved_or_replayed")
            state = "COMPLETED" if reason == "validated_finish" else ("CANCELLED" if reason == "cancel_requested" else "HANDOFF")
            self.db.execute("INSERT INTO outcomes VALUES(?,?,?,?)", (self.run_id, canonical(redact(raw, self.secrets)) if raw is not None else None, canonical(guarded), reason))
            self.db.execute("UPDATE runs SET state=? WHERE run_id=?", (state, self.run_id))
            self.checkpoint()
            self.event("guarded_outcome_recorded", {"reason": reason, "state": state, "guarded": guarded, "host_intervention": reason != "validated_finish", "actual_cost": None, "approval": "NOT_AVAILABLE_U1", "containment": "NOT_IMPLEMENTED"})

    def history(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM attempts WHERE run_id=? ORDER BY seq", (self.run_id,))]

    def close(self):
        self.db.close()
