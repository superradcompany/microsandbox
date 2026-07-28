"""Unit tests for network destination configuration."""

from __future__ import annotations

from microsandbox import (
    Action,
    DestGroup,
    Destination,
    Network,
    NetworkPolicy,
    NetworkProfile,
    Protocol,
    Rule,
)


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


def test_profiles_are_deduplicated_and_canonically_ordered() -> None:
    policy = NetworkPolicy.from_profiles(
        [
            NetworkProfile.HOST,
            NetworkProfile.PRIVATE,
            NetworkProfile.PUBLIC,
            NetworkProfile.PRIVATE,
        ]
    )

    assert policy.default_egress is Action.DENY
    assert policy.default_ingress is Action.ALLOW
    assert [rule.destination for rule in policy.rules[2:]] == [
        Destination.group(DestGroup.PUBLIC),
        Destination.group(DestGroup.PRIVATE),
        Destination.group(DestGroup.HOST),
    ]
    assert policy.rules[:2] == Rule.allow_dns()


def test_empty_profiles_do_not_add_dns() -> None:
    assert NetworkPolicy.from_profiles([]).rules == ()


def test_terminal_policy_constructors_set_both_defaults() -> None:
    assert NetworkPolicy.none() == NetworkPolicy(Action.DENY, Action.DENY)
    assert NetworkPolicy.allow_all() == NetworkPolicy(Action.ALLOW, Action.ALLOW)


def test_unknown_profile_is_rejected() -> None:
    try:
        NetworkPolicy.from_profiles(["bogus"])
    except ValueError as error:
        assert "bogus" in str(error)
    else:
        raise AssertionError("unknown profile should be rejected")


def test_network_profile_convenience_serializes_as_custom_policy() -> None:
    network = Network.from_profiles(NetworkProfile.PUBLIC, NetworkProfile.PRIVATE)
    assert "custom_policy" in network._to_dict()
    assert "policy" not in network._to_dict()


def test_removed_string_presets_fail_with_migration_guidance() -> None:
    try:
        Network(policy="public_only")._to_dict()  # type: ignore[arg-type]
    except TypeError as error:
        assert "Network.from_profiles" in str(error)
    else:
        raise AssertionError("removed string preset should be rejected")


def test_deny_dns_is_action_inverse_of_allow_dns() -> None:
    assert all(rule.action is Action.DENY for rule in Rule.deny_dns())
    assert [rule.protocol for rule in Rule.deny_dns()] == [Protocol.UDP, Protocol.TCP]
