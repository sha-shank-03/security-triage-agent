"""Strict data boundaries shared by the host and provider interface."""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

POLICY_VERSION = "triage-m2-v1"
PROMPT_VERSION = "triage-m2-v1"
PROVIDER_VERSION = "scripted_policy_v2"
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ContractError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_json_key")
        result[key] = value
    return result


def strict_json(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > 65536:
        raise ContractError("invalid_response_size")
    try:
        return json.loads(text, object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              ContractError("non_finite_number")))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("malformed_json") from exc


def keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys():
        raise ContractError("missing_or_invalid_fields")
    if value.keys() - set(required) - set(optional):
        raise ContractError("unknown_fields")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ContractError("invalid_identifier")
    return value


def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractError("timestamp_must_be_utc")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("invalid_timestamp") from exc


def positive_integer(value):
    if type(value) is not int or value < 1:
        raise ContractError("invalid_version")


def decode_turn(text):
    turn = strict_json(text)
    keys(turn, ("tool", "arguments"))
    identifier(turn["tool"])
    if not isinstance(turn["arguments"], dict):
        raise ContractError("arguments_must_be_object")
    return turn


@dataclass(frozen=True)
class Budget:
    max_turns: int = 12
    max_corrections: int = 2
    deadline_seconds: float = 60.0

    def __post_init__(self):
        if type(self.max_turns) is not int or not 1 <= self.max_turns <= 12:
            raise ContractError("invalid_turn_budget")
        if type(self.max_corrections) is not int or not 0 <= self.max_corrections <= 2:
            raise ContractError("invalid_correction_budget")
        if (type(self.deadline_seconds) not in (int, float) or not math.isfinite(self.deadline_seconds)
                or not 0 < self.deadline_seconds <= 60):
            raise ContractError("invalid_deadline")


class DecisionProvider(Protocol):
    """Decisions only: no store, evaluator, credential, or executor handle."""

    name: str

    def next_turn(self, conversation: list[dict], tool_schemas: list[dict],
                  remaining_budget: dict) -> str:
        """Return one JSON tool/arguments envelope; no free-text finalization."""
