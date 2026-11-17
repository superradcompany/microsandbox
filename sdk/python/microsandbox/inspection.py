"""Typed dictionaries for fresh configuration observations, not creation input."""

from typing import Any, Literal, TypedDict


class _RuntimeOptional(TypedDict, total=False):
    guest_clock: Literal["sync", "off"]


class SandboxRuntimeInspection(_RuntimeOptional):
    workdir: str | None
    shell: str | None
    scripts: dict[str, str]
    entrypoint: list[str] | None
    cmd: list[str] | None
    hostname: str | None
    user: str | None
    log_level: str | None
    metrics_sample_interval_ms: int | None
    disable_metrics_sample: bool


class _SpecOptional(TypedDict, total=False):
    name: str
    init: dict[str, Any] | None
    patches: list[dict[str, Any]]
    vsock: dict[str, Any]
    security_profile: str
    deployment_profile: str
    pull_policy: str


class SandboxInspectionSpec(_SpecOptional):
    """Common fields; nested source/network shapes depend on the result's kind.

    Remote image is an OCI string or None for an unavailable non-OCI source.
    Local image is a tagged source mapping. Remote mounts omit source identity;
    remote network secrets contain redacted descriptors, never creation input.
    """

    image: str | dict[str, Any] | None
    resources: dict[str, Any]
    runtime: SandboxRuntimeInspection
    env: list[dict[str, str]]
    labels: dict[str, str]
    rlimits: list[dict[str, Any]]
    lifecycle: dict[str, Any]
    mounts: list[dict[str, Any]]
    network: dict[str, Any]


class SandboxConfigInspection(TypedDict):
    """Persisted observation, not a guarantee of settings applied to a running VM.

    Unavailable/redacted entries are snake_case paths relative to spec.
    Returned dictionaries are snapshots; calling config() again performs I/O.
    """

    kind: Literal["local", "remote"]
    name: str
    spec: SandboxInspectionSpec
    unavailable: list[str]
    redacted: list[str]
