"""Custom HTTP denial messages survive SDK configuration serialization."""

import pytest

from microsandbox import HttpConfig, Network


@pytest.mark.parametrize("message", ["blocked {host}", ""])
def test_http_deny_message_is_preserved(message: str) -> None:
    network = Network(http=HttpConfig(deny_message=message))._to_dict()
    assert network["http"]["deny_message"] == message
    assert network["http"]["deny_response"] is False


def test_http_deny_message_omission_and_validation() -> None:
    assert "http" not in Network()._to_dict()
    assert Network(http=HttpConfig())._to_dict()["http"] == {"deny_response": False}
    enabled = Network(http=HttpConfig(deny_response=True))._to_dict()
    assert enabled["http"] == {"deny_response": True}
    with pytest.raises(TypeError, match="deny_response"):
        Network(http=HttpConfig(deny_response="true"))._to_dict()
    with pytest.raises(TypeError, match="must be HttpConfig"):
        Network(http="invalid")._to_dict()
    with pytest.raises(TypeError, match="deny_message"):
        Network(http=HttpConfig(deny_message=42))._to_dict()
