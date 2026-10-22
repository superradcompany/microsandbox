"""Structured resize observation failures keep verified progress separate from outcomes."""

from microsandbox import MicrosandboxError, ResizeWaitError


def test_native_details_are_exposed_without_parsing_message() -> None:
    error = ResizeWaitError._from_native({
        "reason": "history_unavailable", "sandbox": "box", "operation_id": "old-id",
        "status": [], "message": "retained history is unavailable",
    })
    assert isinstance(error, MicrosandboxError)
    assert error.reason == "history_unavailable"
    assert error.operation_id == "old-id"
    assert error.sandbox == "box"
    assert error.status == []
    assert str(error) == "retained history is unavailable"
