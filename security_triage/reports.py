"""Inspectable records; provenance separates scripts, doubles and model routes."""

import json
import platform
import re
import sqlite3

from .contracts import POLICY_VERSION, PROMPT_VERSION


def _escape(value):
    return re.sub(r"([\\\x60*_{}\[\]()#+.!|<>])", r"\\\1", str(value))


def write_reports(runs, output):
    cases = []
    modes = set()
    for run_id, case_id, snapshot_digest, provider, state, config_json, turns, corrections, expiry in runs.db.execute(
            "SELECT run_id,case_id,snapshot_digest,provider,state,config_json,turns_used,corrections_used,expires_at "
            "FROM runs ORDER BY case_id,run_id"):
        row = runs.db.execute("SELECT final_json FROM dispositions WHERE run_id=?", (run_id,)).fetchone()
        final = json.loads(row[0]) if row else None
        config = json.loads(config_json)
        mode = config["provider"].get("mode", provider)
        modes.add(mode)
        attempts = [{"turn": t, "provider_output": raw, "accepted": bool(ok), "reason": reason,
                     "observed_usage": json.loads(usage)}
                    for t, raw, ok, reason, usage in runs.db.execute(
                        "SELECT turn,raw_json,accepted,reason,usage_json FROM attempts WHERE run_id=? ORDER BY turn",
                        (run_id,))]
        observations = [json.loads(row[0]) for row in runs.db.execute(
            "SELECT observation_json FROM observations WHERE run_id=? ORDER BY turn", (run_id,))]
        proposal = runs.db.execute(
            "SELECT proposal_id,payload_hash,payload_json,state,version FROM proposals WHERE run_id=?", (run_id,)).fetchone()
        cases.append({"case_id": case_id, "run_id": run_id, "snapshot_digest": snapshot_digest,
                      "provider": provider, "configuration": config, "state": state, "final": final,
                      "budget_state": {"turns_used": turns, "corrections_used": corrections, "expires_at": expiry},
                      "attempts": attempts, "observations": observations,
                      "proposal": None if proposal is None else {
                          "proposal_id": proposal[0], "payload_hash": proposal[1],
                          "payload": json.loads(proposal[2]), "state": proposal[3], "version": proposal[4]}})
    mode = ",".join(sorted(modes))
    offline = all(m in ("scripted", "scripted_baseline") for m in modes)
    packet = {"schema_version": 2, "fictional": True, "mode": mode,
              "policy": POLICY_VERSION, "prompt": PROMPT_VERSION,
              "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                              "os": platform.system()},
              "model_usage": {"inference_calls": 0 if offline else None, "tokens": None}, "cases": cases}
    (output / "results.json").write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    lines = ["# Synthetic suspicious-login investigations", "",
             "Mode: **" + _escape(mode) + "**. Fictional authored data.", "",
             "Containment: **NOT_IMPLEMENTED**. Local review records SIMULATED decisions only.", "",
             "Scripted and protocol-double results provide no evidence of real-model reasoning quality.", ""]
    for case in cases:
        final = case["final"]
        lines += ["## " + _escape(case["case_id"]), "", "Run state: " + case["state"] + ".", ""]
        if final:
            lines += [f"Disposition: **{final['disposition']}**; urgency: **{final['urgency']}**.", "",
                      "Stop reason: " + _escape(final["stop_reason"]) + ".", "",
                      "Hypotheses considered: " + ", ".join(_escape(h) for h in final["hypotheses"]) + ".", "",
                      "Evidence claims:", ""]
            for item in final["claims"]:
                lines.append(f"- {_escape(item['kind'])} = {item['value']}; "
                             f"{_escape(item['record_id'])} @ version {item['record_version']}.")
            if not final["claims"]:
                lines.append("- No validated final claims; partial observations remain in results.json.")
            lines += ["", "Evidence gaps: " + (", ".join(_escape(g) for g in final["gaps"]) or "none declared") + ".", ""]
        if case["proposal"]:
            p = case["proposal"]
            lines += [f"Proposal state: **{p['state']}**; version: {p['version']}.",
                      f"Action: {_escape(p['payload']['action'])}; session: {_escape(p['payload']['target_session_id'])}.", "",
                      "Proposal ID: " + p["proposal_id"] + ".", "",
                      "Payload SHA-256: " + p["payload_hash"] + ".", "",
                      "Expires: " + _escape(p["payload"]["expires_at"]) + ".", ""]
        else:
            lines += ["Containment proposal: none.", ""]
        rejected = sum(not a["accepted"] for a in case["attempts"])
        lines += [f"Persisted evidence calls: {len(case['observations'])}; rejected provider turns: {rejected}.", ""]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return packet

