"""Custom HTTP denial messages survive SDK configuration serialization."""

import pytest

from microsandbox import Network


@pytest.mark.parametrize("message", ["blocked {host}", ""])
def test_http_deny_message_is_preserved(message: str) -> None:
    assert Network(http_deny_message=message)._to_dict()["http_deny_message"] == message


def test_http_deny_message_omission_and_validation() -> None:
    assert "http_deny_message" not in Network()._to_dict()
    with pytest.raises(TypeError, match="http_deny_message"):
        Network(http_deny_message=42)._to_dict()
