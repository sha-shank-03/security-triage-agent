"""Finite case-scoped tools with snapshot-bound, two-page event searches."""

from .contracts import ContractError, canonical, digest, identifier, keys, timestamp

STRING = {"type": "string"}
CLAIMS = ("AUTH_SUCCESS", "MFA_DENIED", "DEVICE_MANAGED", "NETWORK_APPROVED",
          "TRAVEL_APPROVED", "RESOURCE_SENSITIVE", "COVERAGE_COMPLETE")


def schema(name, properties, required=()):
    return {"name": name, "parameters": {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}}


CATALOG = [
    schema("get_identity_context", {}),
    schema("search_events", {"kind": {"enum": ["auth", "resource"]},
           **{k: STRING for k in ("session_id", "ip", "from", "to", "cursor")}}, ("kind",)),
    schema("get_device_context", {"device_id": STRING}, ("device_id",)),
    schema("get_network_context", {"ip": STRING}, ("ip",)),
    schema("get_travel_context", {"ip": STRING}, ("ip",)),
    schema("get_telemetry_status", {}),
    schema("finish_investigation", {
        "disposition": {"enum": ["BENIGN", "ESCALATE", "INCONCLUSIVE"]},
        "urgency": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "claims": {"type": "array", "minItems": 1, "maxItems": 12, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["kind", "record_id", "record_version", "value"], "properties": {
                "kind": {"enum": list(CLAIMS)}, "record_id": STRING,
                "record_version": {"type": "integer", "minimum": 1}, "value": {"type": "boolean"}}}},
        "gaps": {"type": "array", "maxItems": 4, "items": STRING},
        "hypotheses": {"type": "array", "minItems": 1, "maxItems": 3,
                       "items": {"enum": ["APPROVED_NETWORK", "APPROVED_TRAVEL",
                                         "UNAUTHORIZED_ACCOUNT_USE", "MISSING_TELEMETRY"]}},
        "reason": {"enum": ["corroborated_benign_context", "supported_account_misuse",
                           "insufficient_evidence"]},
        "proposal": {"anyOf": [{"type": "null"}, {"type": "object",
            "additionalProperties": False,
            "required": ["action", "target_session_id", "target_record_id", "target_record_version"],
            "properties": {"action": {"enum": ["REVOKE_SESSION"]}, "target_session_id": STRING,
                           "target_record_id": STRING,
                           "target_record_version": {"type": "integer", "minimum": 1}}}]}},
        ("disposition", "urgency", "claims", "gaps", "hypotheses", "reason", "proposal")),
]


class EvidenceTools:
    def __init__(self, store):
        self.store = store
        self.seen = {}
        self.observations = []
        self.cursors = {}
        self.pages = {}

    def _known(self, field):
        result = {self.store.snapshot["alert"][field]}
        result.update(r["data"][field] for r in self.seen.values() if field in r["data"])
        return result

    def remember(self, observation):
        if observation["snapshot_digest"] != self.store.snapshot_digest:
            raise ContractError("observation_snapshot_mismatch")
        originals = {r["id"]: r for r in self.store.snapshot["records"]}
        for record in observation["records"]:
            if record != originals.get(record["id"]):
                raise ContractError("observation_record_corrupt")
        self.seen.update({r["id"]: r for r in observation["records"]})
        self.observations.append(observation)
        if observation["tool"] == "search_events":
            base = {k: v for k, v in observation["arguments"].items() if k != "cursor"}
            key = digest(base)
            offset = observation["offset"]
            self.pages.setdefault(key, set()).add(offset)
            if observation["next_cursor"]:
                self.cursors[observation["next_cursor"]] = (key, offset + 50)

    def complete_event_read(self, kind):
        chain = [o for o in self.observations if o["tool"] == "search_events"
                 and {k: v for k, v in o["arguments"].items() if k != "cursor"} == {"kind": kind}]
        return bool(chain and not chain[-1]["truncated"])

    def call(self, name, arguments):
        offset, next_cursor = 0, None
        if name == "get_identity_context":
            keys(arguments, ())
            records = self.store.records("identity")
        elif name == "search_events":
            keys(arguments, ("kind",), ("session_id", "ip", "from", "to", "cursor"))
            if arguments["kind"] not in ("auth", "resource"):
                raise ContractError("invalid_event_kind")
            records = self.store.records(arguments["kind"])
            if "session_id" in arguments:
                identifier(arguments["session_id"])
                known = {r["data"]["session_id"] for r in self.seen.values() if r["kind"] == "auth"}
                if arguments["session_id"] not in known:
                    raise ContractError("unobserved_session")
                records = [r for r in records if r["data"]["session_id"] == arguments["session_id"]]
            if "ip" in arguments:
                if not isinstance(arguments["ip"], str) or arguments["ip"] not in self._known("ip"):
                    raise ContractError("unobserved_ip")
                records = [r for r in records if r["data"].get("ip") == arguments["ip"]]
            start = timestamp(arguments.get("from", self.store.snapshot["window_start"]))
            end = timestamp(arguments.get("to", self.store.snapshot["cutoff"]))
            if not (timestamp(self.store.snapshot["window_start"]) <= start <= end
                    <= timestamp(self.store.snapshot["cutoff"])):
                raise ContractError("query_outside_case_window")
            records = [r for r in records if start <= timestamp(r["event_time"]) <= end]
            base = {k: v for k, v in arguments.items() if k != "cursor"}
            key = digest(base)
            if "cursor" in arguments:
                identifier(arguments["cursor"])
                saved = self.cursors.get(arguments["cursor"])
                if not saved or saved[0] != key:
                    raise ContractError("unissued_or_mismatched_cursor")
                offset = saved[1]
            if offset not in (0, 50) or offset in self.pages.get(key, set()):
                raise ContractError("page_budget_or_duplicate_query")
            if len(records) > offset + 50 and offset == 0:
                next_cursor = digest({"snapshot": self.store.snapshot_digest, "query": base, "offset": 50})[:24]
        elif name == "get_device_context":
            keys(arguments, ("device_id",))
            identifier(arguments["device_id"])
            if arguments["device_id"] not in self._known("device_id"):
                raise ContractError("unobserved_device")
            records = [r for r in self.store.records("device") if r["data"]["device_id"] == arguments["device_id"]]
        elif name in ("get_network_context", "get_travel_context"):
            keys(arguments, ("ip",))
            if not isinstance(arguments["ip"], str) or arguments["ip"] not in self._known("ip"):
                raise ContractError("unobserved_ip")
            snapshot = self.store.snapshot
            kind = "network" if name == "get_network_context" else "travel"
            records = [r for r in self.store.records(kind) if r["data"]["ip"] == arguments["ip"]
                       and timestamp(r["data"]["valid_from"]) <= timestamp(snapshot["window_start"])
                       and timestamp(r["data"]["valid_to"]) >= timestamp(snapshot["cutoff"])]
        elif name == "get_telemetry_status":
            keys(arguments, ())
            records = self.store.records("coverage")
        else:
            raise ContractError("unknown_evidence_tool")
        truncated = len(records) > offset + 50
        observation = {"observation_id": digest({"tool": name, "args": arguments,
                       "snapshot": self.store.snapshot_digest})[:24], "tool": name,
                       "arguments": dict(arguments), "snapshot_digest": self.store.snapshot_digest,
                       "status": "partial" if truncated else ("ok" if records else "empty"),
                       "truncated": truncated, "offset": offset, "next_cursor": next_cursor,
                       "records": records[offset:offset + 50]}
        if len(canonical(observation).encode("utf-8")) > 16384:
            raise ContractError("observation_byte_budget")
        self.remember(observation)
        return observation

