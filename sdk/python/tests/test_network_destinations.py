"""Unit tests for network destination configuration."""

from __future__ import annotations

from microsandbox import DestGroup, Destination, NetworkPolicy, Protocol, Rule


def test_typed_ip_destination_serializes_with_kind() -> None:
    policy = NetworkPolicy(
        rules=(
            Rule.allow(
                destination=Destination.ip("1.1.1.1"),
                protocol=Protocol.TCP,
                port=443,
            ),
        ),
    )

    assert policy._to_dict()["rules"] == [
        {
            "action": "allow",
            "direction": "egress",
            "destination_kind": "ip",
            "destination": "1.1.1.1",
            "protocol": "tcp",
            "port": "443",
        }
    ]


def test_typed_group_destination_serializes_with_kind() -> None:
    policy = NetworkPolicy(
        rules=(Rule.allow(destination=Destination.group(DestGroup.PUBLIC)),),
    )

    assert policy._to_dict()["rules"] == [
        {
            "action": "allow",
            "direction": "egress",
            "destination_kind": "group",
            "destination": "public",
        }
    ]


def test_string_destination_remains_compatibility_shorthand() -> None:
    policy = NetworkPolicy(
        rules=(
            Rule.allow(
                destination="github.com",
                protocol=Protocol.TCP,
                port=443,
            ),
        ),
    )

    assert policy._to_dict()["rules"] == [
        {
            "action": "allow",
            "direction": "egress",
            "destination": "github.com",
            "protocol": "tcp",
            "port": "443",
        }
    ]
