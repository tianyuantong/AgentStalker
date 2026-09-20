"""Small, versioned contracts for evidence, not a deployment/config framework."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import uuid

SCHEMA_VERSION = 2
SCOPE_KEYS = ("run_id", "case_id", "attempt_id", "session_id")
EXECUTION_STATES = {"completed", "error", "timeout", "not_run"}
COLLECTION_STATES = {"ok", "error", "not_enabled"}


@dataclass(frozen=True)
class RunContext:
    run_id: str
    case_id: str
    attempt_id: str
    session_id: str

    @classmethod
    def new(cls, case_id: str, run_id: str | None = None, attempt_id: str = "1"):
        return cls(run_id or uuid.uuid4().hex, case_id, attempt_id, uuid.uuid4().hex)

    def to_dict(self):
        return asdict(self)


def same_scope(record: dict, context: dict) -> bool:
    return bool(context) and all(
        isinstance(context.get(k), str) and bool(context[k]) and record.get(k) == context[k]
        for k in SCOPE_KEYS
    )


def validate_context(context: dict) -> None:
    if not isinstance(context, dict) or not same_scope(context, context):
        raise ValueError("run/case/attempt/session identity is required")


def validate_v2(data: dict) -> None:
    """Structural checks at the trust boundary. Missing observations stay unknown."""
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported evidence schema version")
    if not isinstance(data.get("metadata", {}), dict):
        raise ValueError("metadata must be an object")
    validate_context(data.get("context"))
    if data.get("test_case_id") != data["context"]["case_id"]:
        raise ValueError("case identity mismatch")
    execution = data.get("execution")
    if not isinstance(execution, dict) or execution.get("status") not in EXECUTION_STATES:
        raise ValueError("invalid execution status")
    if execution.get("reset_status") not in {"ok", "error", "unknown"}:
        raise ValueError("invalid reset status")
    collection = data.get("collection")
    if not isinstance(collection, dict):
        raise ValueError("collection must be an object")
    for name, state in collection.items():
        if not isinstance(state, dict) or state.get("status") not in COLLECTION_STATES:
            raise ValueError(f"invalid collection status: {name}")
        if not isinstance(state.get("window_complete"), bool):
            raise ValueError(f"missing observation window state: {name}")
        if not isinstance(state.get("method"), str) or not state["method"]:
            raise ValueError(f"missing collection method: {name}")
    required = data.get("required_sources")
    if not isinstance(required, list) or not all(isinstance(x, str) and x for x in required):
        raise ValueError("required_sources must be a list of names")
    if len(required) != len(set(required)):
        raise ValueError("duplicate required source")
    for field in ("events", "checks"):
        if not isinstance(data.get(field), list) or not all(isinstance(x, dict) for x in data[field]):
            raise ValueError(f"invalid {field}")
    ids = [e.get("event_id") for e in data["events"]]
    if any(not isinstance(i, str) or not i for i in ids) or len(ids) != len(set(ids)):
        raise ValueError("events require unique identifiers")
    for event in data["events"]:
        validate_context(event)
        if not isinstance(event.get("source"), str) or not isinstance(event.get("data"), dict):
            raise ValueError("invalid observation source/data")
    check_ids = [c.get("id") for c in data["checks"]]
    if any(not isinstance(i, str) or not i for i in check_ids) or len(check_ids) != len(set(check_ids)):
        raise ValueError("checks require unique identifiers")
    if not isinstance(data.get("boundary", ""), str):
        raise ValueError("boundary must be text")


def canonical_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def file_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json_new(path: str | Path, value) -> None:
    """Exclusive creation: repeats must never erase an earlier experiment."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write("\n")


def load_json(path: str | Path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError(f"invalid JSON constant: {value}")
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs,
                      parse_constant=invalid)
