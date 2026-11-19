"""Managed-job value types. Output data is always bytes; timestamps are Unix milliseconds."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Literal

from .types import StrEnum


class JobState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    EXITED = "exited"
    FAILED = "failed"
    LOST = "lost"


class JobOutputSource(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    OUTPUT = "output"
    STDIN_ERROR = "stdin_error"


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
    source: JobOutputSource
    data: bytes
    cursor: str


@dataclass(frozen=True)
class JobOutputEvent:
    value: JobLogEntry
    type: Literal["output"] = field(default="output", init=False)


@dataclass(frozen=True)
class JobGapEvent:
    value: dict[str, str]
    type: Literal["gap"] = field(default="gap", init=False)


@dataclass(frozen=True)
class JobCompletedEvent:
    value: JobInfo
    type: Literal["completed"] = field(default="completed", init=False)


JobEvent = JobOutputEvent | JobGapEvent | JobCompletedEvent


def _decode_info(value: dict) -> JobInfo:
    fields = {key: value[key] for key in JobInfo.__dataclass_fields__}
    fields["state"] = JobState(fields["state"])
    return JobInfo(**fields)


def _decode_page(value: dict) -> JobPage:
    return JobPage([_decode_info(item) for item in value["items"]], value["next_cursor"])


def _decode_exit(value: dict) -> JobExit:
    return JobExit(**value)


def _decode_log(value: dict) -> JobLogEntry:
    return JobLogEntry(
        value["timestamp"],
        JobOutputSource(value["source"]),
        base64.b64decode(value["data_base64"], validate=True),
        value["cursor"],
    )


def _decode_logs(value: list[dict]) -> list[JobLogEntry]:
    return [_decode_log(item) for item in value]


def _decode_event(value: dict) -> JobEvent:
    kind = value["type"]
    payload = value["value"]
    if kind == "output":
        return JobOutputEvent(_decode_log(payload))
    if kind == "completed":
        return JobCompletedEvent(_decode_info(payload))
    if kind == "gap":
        return JobGapEvent(payload)
    raise ValueError(f"Unknown job event {kind!r}")
