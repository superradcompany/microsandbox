"""Unit tests for secret placeholder passthrough configuration."""

from __future__ import annotations

from microsandbox import Network, Sandbox, Secret, ViolationAction, ViolationPolicy


def test_violation_action_includes_passthrough() -> None:
    assert ViolationAction.PASSTHROUGH == "passthrough"


def test_secret_passthrough_hosts_serialize() -> None:
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow_hosts=("api.github.com",),
        on_violation=ViolationPolicy.passthrough(
            hosts=("api.anthropic.com",),
            host_patterns=("*.anthropic.com",),
        ),
    )

    assert secret._to_dict() == {
        "env_var": "API_KEY",
        "value": "sk-abc",
        "allow_hosts": ["api.github.com"],
        "on_violation": {
            "passthrough": {
                "hosts": ["api.anthropic.com"],
                "host_patterns": ["*.anthropic.com"],
            }
        },
    }


def test_network_secret_passthrough_hosts_serialize() -> None:
    network = Network(
        on_secret_violation=ViolationPolicy.passthrough(all_hosts=True),
    )

    assert network._to_dict() == {
        "on_secret_violation": {
            "passthrough": {
                "all_hosts": True,
            }
        },
    }


def _native_create_error(**kwargs: object) -> BaseException:
    """Probe the native kwarg parser without booting a sandbox.

    ``Sandbox.create`` parses kwargs synchronously before its async
    transition, so a parse failure raises its own error while a successful
    parse fails later for lack of a running asyncio loop. Comparing against
    a known-good baseline isolates the parse stage.
    """
    try:
        Sandbox.create("violation-parse-probe", image="alpine", **kwargs)
    except BaseException as exc:
        return exc
    raise AssertionError("expected Sandbox.create to raise outside an event loop")


def test_native_create_accepts_violation_policy_fallback_objects() -> None:
    baseline = _native_create_error(on_secret_violation="block")
    for policy in (
        ViolationPolicy.block(),
        ViolationPolicy.block_and_log(),
        ViolationPolicy.block_and_terminate(),
        ViolationAction.BLOCK_AND_TERMINATE,
    ):
        exc = _native_create_error(on_secret_violation=policy)
        assert type(exc) is type(baseline), f"{policy!r} rejected by parser: {exc!r}"


def test_native_create_accepts_violation_policy_passthrough_objects() -> None:
    baseline = _native_create_error(on_secret_violation="block")
    exc = _native_create_error(
        on_secret_violation=ViolationPolicy.passthrough(hosts=("api.example.com",)),
    )
    assert type(exc) is type(baseline), f"passthrough policy rejected by parser: {exc!r}"


def test_native_create_accepts_secret_violation_policy_fallback_objects() -> None:
    baseline = _native_create_error(on_secret_violation="block")
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow_hosts=("api.example.com",),
        on_violation=ViolationPolicy.block_and_terminate(),
    )
    exc = _native_create_error(secrets=[secret])
    assert type(exc) is type(baseline), f"per-secret policy rejected by parser: {exc!r}"


def test_native_create_rejects_unknown_violation_action() -> None:
    exc = _native_create_error(on_secret_violation="never-heard-of-it")
    assert isinstance(exc, ValueError)
    assert "unknown violation action" in str(exc)
