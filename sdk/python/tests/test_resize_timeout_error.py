"""Resize timeouts keep the last observed status."""

from microsandbox import MicrosandboxError, ResizeTimeoutError


def test_status_is_structured() -> None:
    status = [
        {
            "resource": "cpus",
            "requested": "4",
            "actual": "2",
            "enforced": "4",
            "state": "converging",
        }
    ]
    error = ResizeTimeoutError("timed out", status=status)
    assert isinstance(error, MicrosandboxError)
    assert isinstance(error, TimeoutError)
    assert error.code == "resize-timeout"
    assert str(error) == "timed out"
    assert error.status == status


def test_status_defaults_to_empty() -> None:
    assert ResizeTimeoutError("timed out").status == []
