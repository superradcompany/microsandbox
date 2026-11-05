"""Managed-job value types. Output data is always bytes; timestamps are Unix milliseconds."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Literal

JobState = Literal["starting", "running", "exited", "failed", "lost"]


@dataclass(frozen=True)
class JobInfo:
    id: str
    runtime_boot_id: str
    command: list[str]
    state: JobState
    tty: bool
    stdin_closed: bool
    pid: int | None
    created_at: int
    started_at: int | None
    finished_at: int | None
    exit_code: int | None
    failure: dict | None
    error: str | None
    timed_out: bool


@dataclass(frozen=True)
class JobPage:
    items: list[JobInfo]
    next_cursor: str | None


@dataclass(frozen=True)
class JobExit:
    code: int
    success: bool
    timed_out: bool


@dataclass(frozen=True)
class JobLogEntry:
    timestamp: int
    source: str
    data: bytes
    cursor: str


@dataclass(frozen=True)
class JobEvent:
    type: Literal["output", "gap", "completed"]
    value: JobLogEntry | JobInfo | dict[str, str]


def _decode_info(value: dict) -> JobInfo:
    return JobInfo(**{key: value[key] for key in JobInfo.__dataclass_fields__})


def _decode_page(value: dict) -> JobPage:
    return JobPage([_decode_info(item) for item in value["items"]], value["next_cursor"])


def _decode_exit(value: dict) -> JobExit:
    return JobExit(**value)


def _decode_log(value: dict) -> JobLogEntry:
    return JobLogEntry(
        value["timestamp"],
        value["source"],
        base64.b64decode(value["data_base64"], validate=True),
        value["cursor"],
    )


def _decode_logs(value: list[dict]) -> list[JobLogEntry]:
    return [_decode_log(item) for item in value]


def _decode_event(value: dict) -> JobEvent:
    kind = value["type"]
    payload = value["value"]
    if kind == "output":
        payload = _decode_log(payload)
    elif kind == "completed":
        payload = _decode_info(payload)
    return JobEvent(kind, payload)
