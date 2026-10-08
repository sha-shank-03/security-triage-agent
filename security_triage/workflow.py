"""Durable workflow counters, immutable proposals, and local review audit."""

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .contracts import (Budget, ContractError, POLICY_VERSION, PROMPT_VERSION,
                        canonical, digest, identifier)


def utc_now():
    return datetime.now(timezone.utc)


def iso(value):
    if value.tzinfo is None:
        raise ContractError("clock_must_be_timezone_aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class RunStore:
    def __init__(self, path, clock=utc_now):
        self.clock = clock
        self.db = sqlite3.connect(path, timeout=1)
        self.db.execute("PRAGMA foreign_keys=ON")
        if self.db.execute("PRAGMA user_version").fetchone()[0] not in (0, 2):
            self.db.close()
            raise ContractError("workflow_schema_changed_use_fresh_output")
        self.db.executescript("""
            PRAGMA user_version=2;
            CREATE TABLE IF NOT EXISTS runs(
                run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, snapshot_digest TEXT NOT NULL,
                provider TEXT NOT NULL, policy TEXT NOT NULL, prompt TEXT NOT NULL, state TEXT NOT NULL,
                request_id TEXT NOT NULL, config_json TEXT NOT NULL, turns_used INTEGER NOT NULL,
                corrections_used INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                cancel_requested INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts(
                run_id TEXT NOT NULL REFERENCES runs(run_id), turn INTEGER NOT NULL,
                raw_json TEXT NOT NULL, accepted INTEGER NOT NULL, reason TEXT NOT NULL,
                usage_json TEXT NOT NULL, PRIMARY KEY(run_id,turn));
            CREATE TABLE IF NOT EXISTS observations(
                run_id TEXT NOT NULL REFERENCES runs(run_id), turn INTEGER NOT NULL,
                observation_json TEXT NOT NULL, PRIMARY KEY(run_id,turn));
            CREATE TABLE IF NOT EXISTS dispositions(
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id), final_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS proposals(
                proposal_id TEXT PRIMARY KEY, run_id TEXT UNIQUE NOT NULL REFERENCES runs(run_id),
                payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL,
                version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS current_snapshots(
                case_id TEXT PRIMARY KEY, version INTEGER NOT NULL, digest TEXT NOT NULL, context_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reviews(
                request_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
                request_hash TEXT NOT NULL, result_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_events(
                event_id INTEGER PRIMARY KEY, event TEXT NOT NULL, object_id TEXT NOT NULL,
                data_json TEXT NOT NULL, created_at TEXT NOT NULL);
        """)

    def audit(self, event, object_id, data):
        self.db.execute("INSERT INTO audit_events(event,object_id,data_json,created_at) VALUES(?,?,?,?)",
                        (event, object_id, canonical(data), iso(self.clock())))

    def register_snapshot(self, evidence):
        snapshot = evidence.snapshot
        identity = next(r for r in snapshot["records"] if r["kind"] == "identity")
        context = {"user_id": snapshot["alert"]["user_id"], "identity_id": identity["id"],
                   "identity_version": identity["version"],
                   "sessions": {r["id"]: {"session_id": r["data"]["session_id"], "version": r["version"]}
                                for r in snapshot["records"] if r["kind"] == "auth" and r["data"]["outcome"] == "success"}}
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            saved = self.db.execute("SELECT version,digest FROM current_snapshots WHERE case_id=?",
                                    (evidence.case_id,)).fetchone()
            version = snapshot["snapshot_version"]
            if saved and (version < saved[0] or (version == saved[0] and evidence.snapshot_digest != saved[1])):
                raise ContractError("snapshot_version_conflict")
            if saved and version == saved[0]:
                return
            self.db.execute("INSERT INTO current_snapshots VALUES(?,?,?,?) ON CONFLICT(case_id) DO UPDATE "
                            "SET version=excluded.version,digest=excluded.digest,context_json=excluded.context_json",
                            (evidence.case_id, version, evidence.snapshot_digest, canonical(context)))
            self.audit("snapshot_registered", evidence.case_id, {"version": version, "digest": evidence.snapshot_digest})

    def start(self, evidence, provider, budget=Budget(), configuration=None, request_id="default", resume=False):
        identifier(provider)
        identifier(request_id)
        config = {"provider": configuration or {"name": provider}, "budget": asdict(budget),
                  "policy": POLICY_VERSION, "prompt": PROMPT_VERSION, "tool_protocol": "m2-v1"}
        run_id = digest({"case": evidence.case_id, "snapshot": evidence.snapshot_digest,
                         "request": request_id, "config": config})[:24]
        saved = self.db.execute("SELECT state,turns_used FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if saved is None and resume:
            raise ContractError("resume_configuration_or_snapshot_mismatch")
        if saved and saved[0] == "CANCELLED":
            raise ContractError("cancelled_run_cannot_resume")
        if saved and saved[0] != "COMPLETED" and saved[1] and not resume:
            raise ContractError("run_requires_explicit_resume")
        self.register_snapshot(evidence)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if saved is None:
                now = self.clock()
                self.db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    run_id, evidence.case_id, evidence.snapshot_digest, provider, POLICY_VERSION,
                    PROMPT_VERSION, "INVESTIGATING", request_id, canonical(config), 0, 0,
                    iso(now), iso(now + timedelta(seconds=budget.deadline_seconds)), 0))
            elif resume:
                self.db.execute("UPDATE attempts SET reason='provider_request_interrupted' "
                                "WHERE run_id=? AND reason='REQUEST_STARTED'", (run_id,))
                self.audit("run_resumed", run_id, {"turns_used": saved[1]})
        return run_id, bool(saved and saved[0] == "COMPLETED")

    def state(self, run_id):
        row = self.db.execute("SELECT state,turns_used,corrections_used,expires_at,cancel_requested,config_json "
                              "FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise ContractError("unknown_run")
        return {"state": row[0], "turns_used": row[1], "corrections_used": row[2], "expires_at": row[3],
                "cancel_requested": bool(row[4]), "config": json.loads(row[5])}

    def reserve_turn(self, run_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            state = self.state(run_id)
            if state["state"] != "INVESTIGATING" or state["cancel_requested"]:
                raise ContractError("run_not_active")
            if state["turns_used"] >= state["config"]["budget"]["max_turns"]:
                raise ContractError("turn_budget_exhausted")
            if state["corrections_used"] > state["config"]["budget"]["max_corrections"]:
                raise ContractError("correction_budget_exhausted")
            if self.clock() >= datetime.fromisoformat(state["expires_at"].replace("Z", "+00:00")):
                raise ContractError("deadline_exhausted")
            turn = state["turns_used"] + 1
            self.db.execute("UPDATE runs SET turns_used=? WHERE run_id=?", (turn, run_id))
            self.db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?)",
                            (run_id, turn, "{}", 0, "REQUEST_STARTED", "{}"))
        return turn

    def record(self, run_id, turn, raw, accepted, reason, observation=None, usage=None, final=None, evidence=None):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if final is not None and self.state(run_id)["cancel_requested"]:
                raise ContractError("cancel_requested")
            updated = self.db.execute("UPDATE attempts SET raw_json=?,accepted=?,reason=?,usage_json=? "
                                      "WHERE run_id=? AND turn=? AND reason='REQUEST_STARTED'",
                                      (raw, int(accepted), reason, canonical(usage or {}), run_id, turn))
            if updated.rowcount != 1:
                raise ContractError("attempt_not_reserved_or_already_recorded")
            if not accepted and reason not in ("provider_request_interrupted", "cancel_requested"):
                self.db.execute("UPDATE runs SET corrections_used=corrections_used+1 WHERE run_id=?", (run_id,))
            if observation is not None:
                self.db.execute("INSERT INTO observations VALUES(?,?,?)", (run_id, turn, canonical(observation)))
            if final is not None:
                self._finish(run_id, final, evidence)

    def _finish(self, run_id, final, evidence):
        state = self.state(run_id)
        if state["state"] != "INVESTIGATING" or state["cancel_requested"]:
            raise ContractError("run_not_active")
        if (final.get("stop_reason") == "validated_finish"
                and self.clock() >= datetime.fromisoformat(state["expires_at"].replace("Z", "+00:00"))):
            raise ContractError("deadline_exhausted")
        if final.get("proposal"):
            current = self.db.execute("SELECT version,digest,context_json FROM current_snapshots WHERE case_id=?",
                                      (evidence.case_id,)).fetchone()
            if current[1] != evidence.snapshot_digest:
                raise ContractError("snapshot_superseded")
            context = json.loads(current[2])
            now = self.clock()
            payload = {**final["proposal"], "case_id": evidence.case_id, "snapshot_version": current[0],
                       "snapshot_digest": current[1], "identity_id": context["identity_id"],
                       "identity_version": context["identity_version"], "user_id": context["user_id"],
                       "policy": POLICY_VERSION, "version": 1, "execution_status": "NOT_IMPLEMENTED",
                       "created_at": iso(now), "expires_at": iso(now + timedelta(hours=24)),
                       "evidence_refs": final["claims"]}
            payload_hash = digest(payload)
            self.db.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?)",
                            (payload_hash[:24], run_id, payload_hash, canonical(payload), "PENDING", 1))
        self.db.execute("INSERT INTO dispositions VALUES(?,?)", (run_id, canonical(final)))
        self.db.execute("UPDATE runs SET state='COMPLETED' WHERE run_id=?", (run_id,))
        self.audit("run_completed", run_id, {"disposition": final["disposition"], "stop_reason": final["stop_reason"]})

    def finish(self, run_id, final, evidence):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._finish(run_id, final, evidence)

    def request_cancel(self, run_id):
        identifier(run_id)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.state(run_id)["state"] != "INVESTIGATING":
                raise ContractError("run_not_active")
            self.db.execute("UPDATE runs SET cancel_requested=1 WHERE run_id=?", (run_id,))
            self.audit("cancel_requested", run_id, {})

    def cancel(self, run_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            state = self.state(run_id)["state"]
            if state == "CANCELLED":
                return
            if state != "INVESTIGATING":
                raise ContractError("run_not_active")
            self.db.execute("UPDATE runs SET state='CANCELLED',cancel_requested=1 WHERE run_id=?", (run_id,))
            self.audit("run_cancelled", run_id, {"execution_status": "NOT_IMPLEMENTED"})

    def history(self, run_id):
        return self.db.execute("SELECT a.turn,a.raw_json,a.accepted,a.reason,o.observation_json "
                               "FROM attempts a LEFT JOIN observations o ON a.run_id=o.run_id AND a.turn=o.turn "
                               "WHERE a.run_id=? ORDER BY a.turn", (run_id,)).fetchall()

    def close(self):
        self.db.close()
