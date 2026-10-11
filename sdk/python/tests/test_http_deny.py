"""Custom HTTP denial messages survive SDK configuration serialization."""

import pytest

from microsandbox import HttpConfig, Network


@pytest.mark.parametrize("field", ["deny_message", "network_deny_message", "secret_deny_message"])
@pytest.mark.parametrize("message", ["blocked {host}", ""])
def test_http_deny_messages_are_preserved(field: str, message: str) -> None:
    network = Network(http=HttpConfig(**{field: message}))._to_dict()
    assert network["http"][field] == message
    assert network["http"]["deny_response"] is True


def test_http_deny_messages_omission_and_validation() -> None:
    assert "http" not in Network()._to_dict()
    assert Network(http=HttpConfig())._to_dict()["http"] == {
        "deny_response": True,
        "deny_response_format": "json",
    }
    enabled = Network(http=HttpConfig(deny_response=True))._to_dict()
    assert enabled["http"] == {"deny_response": True, "deny_response_format": "json"}
    assert (
        Network(http=HttpConfig(deny_response=False))._to_dict()["http"]["deny_response"] is False
    )
    with pytest.raises(TypeError, match="deny_response"):
        Network(http=HttpConfig(deny_response="true"))._to_dict()
    with pytest.raises(TypeError, match="must be HttpConfig"):
        Network(http="invalid")._to_dict()
    for field in ["deny_message", "network_deny_message", "secret_deny_message"]:
        with pytest.raises(TypeError, match=field):
            Network(http=HttpConfig(**{field: 42}))._to_dict()


def test_http_deny_legacy_positional_and_json_format() -> None:
    assert Network(http=HttpConfig(True, "blocked {host}", deny_response_format="text"))._to_dict()[
        "http"
    ] == {
        "deny_response": True,
        "deny_response_format": "text",
        "deny_message": "blocked {host}",
    }
    assert (
        Network(http=HttpConfig(deny_response_format="json"))._to_dict()["http"][
            "deny_response_format"
        ]
        == "json"
    )
    with pytest.raises(ValueError, match="deny_response_format"):
        Network(http=HttpConfig(deny_response_format="xml"))._to_dict()
