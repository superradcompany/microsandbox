"""Byte preservation and typed metadata at the managed-job binding boundary."""

import pytest

from microsandbox import JobCompletedEvent, JobGapEvent, JobOutputEvent, JobOutputSource, JobState
from microsandbox.errors import JobError
from microsandbox.jobs import _decode_event, _decode_logs, _decode_page


def test_job_binary_output_and_cursor():
    entry = _decode_logs(
        [{"timestamp": 1, "source": "stdout", "data_base64": "/wAK", "cursor": "job_1:1"}]
    )[0]
    assert entry.data == b"\xff\x00\n"
    assert entry.source is JobOutputSource.STDOUT
    assert entry.cursor == "job_1:1"


def test_job_gap_and_empty_page():
    event = _decode_event({"type": "gap", "value": {"cursor": "job_1:10"}})
    assert isinstance(event, JobGapEvent)
    assert event.type == "gap"
    assert event.value == {"cursor": "job_1:10"}
    assert _decode_page({"items": [], "next_cursor": None}).items == []


def test_uncertain_launch_keeps_recovery_id():
    error = JobError("launch_unconfirmed", "inspect before retry", "job_1")
    assert error.code == "launch_unconfirmed"
    assert error.job_id == "job_1"


@pytest.mark.parametrize("source", list(JobOutputSource))
def test_job_output_event(source):
    event = _decode_event(
        {
            "type": "output",
            "value": {
                "timestamp": 1,
                "source": source.value,
                "data_base64": "",
                "cursor": "1",
            },
        }
    )
    assert isinstance(event, JobOutputEvent)
    assert event.value.source is source


@pytest.mark.parametrize("state", list(JobState))
def test_completed_event_preserves_job_state(state):
    payload = dict(
        id="job",
        runtime_boot_id="boot",
        command=[],
        state=state.value,
        tty=False,
        stdin_closed=True,
        pid=None,
        created_at=1,
        started_at=None,
        finished_at=None,
        exit_code=None,
        failure=None,
        error=None,
        timed_out=False,
    )
    event = _decode_event({"type": "completed", "value": payload})
    assert isinstance(event, JobCompletedEvent)
    assert event.value.state is state
