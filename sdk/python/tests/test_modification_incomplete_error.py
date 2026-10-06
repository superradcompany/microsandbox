"""An unsettled modification keeps the operation id needed to resume it."""

import pytest

from microsandbox import MicrosandboxError, ModificationIncompleteError


@pytest.mark.parametrize("committed", [True, False, None])
def test_operation_id_and_commit_state_are_structured(committed: bool | None) -> None:
    error = ModificationIncompleteError(
        "sandbox modification operation did not finish",
        operation_id="op-1",
        budget=60.0,
        committed=committed,
    )
    assert isinstance(error, MicrosandboxError)
    assert isinstance(error, TimeoutError)
    assert error.code == "modification-incomplete"
    assert error.operation_id == "op-1"
    assert error.budget == 60.0
    assert error.committed is committed
