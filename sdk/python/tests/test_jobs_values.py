"""Byte preservation and typed metadata at the managed-job binding boundary."""

from microsandbox.errors import JobError
from microsandbox.jobs import _decode_event, _decode_logs, _decode_page


def test_job_binary_output_and_cursor():
    entry = _decode_logs(
        [{"timestamp": 1, "source": "stdout", "data_base64": "/wAK", "cursor": "job_1:1"}]
    )[0]
    assert entry.data == b"\xff\x00\n"
    assert entry.cursor == "job_1:1"


def test_job_gap_and_empty_page():
    event = _decode_event({"type": "gap", "value": {"cursor": "job_1:10"}})
    assert event.type == "gap"
    assert event.value == {"cursor": "job_1:10"}
    assert _decode_page({"items": [], "next_cursor": None}).items == []


def test_uncertain_launch_keeps_recovery_id():
    error = JobError("launch_unconfirmed", "inspect before retry", "job_1")
    assert error.code == "launch_unconfirmed"
    assert error.job_id == "job_1"
