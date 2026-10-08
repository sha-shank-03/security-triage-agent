"""Frozen fixed-read baseline: six reads, then one deterministic finalization."""

from .contracts import canonical
from .providers import finish_from_observations

BASELINE_VERSION = "fixed_six_reads_v1"


class FixedBaseline:
    name = BASELINE_VERSION
    configuration = {"name": BASELINE_VERSION, "mode": "scripted_baseline", "model": None}

    def next_turn(self, conversation, tool_schemas, remaining_budget):
        alert = conversation[1]["alert"]
        reads = [
            ("get_identity_context", {}),
            ("search_events", {"kind": "auth"}),
            ("get_telemetry_status", {}),
            ("get_device_context", {"device_id": alert["device_id"]}),
            ("get_network_context", {"ip": alert["ip"]}),
            ("search_events", {"kind": "resource"}),
        ]
        observations = [m["observation"] for m in conversation if m["role"] == "tool"]
        for tool, arguments in reads:
            if not any(o["tool"] == tool and o["arguments"] == arguments for o in observations):
                return canonical({"tool": tool, "arguments": arguments})
        return canonical({"tool": "finish_investigation", "arguments": finish_from_observations(conversation)})
