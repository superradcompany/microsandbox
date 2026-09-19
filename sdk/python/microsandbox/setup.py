"""Resolve and install matched host runtime binaries."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Literal

from microsandbox import _microsandbox as native

RuntimeOrigin = Literal["environment", "sdk_package", "configuration", "home", "installed"]


@dataclass(frozen=True)
class RuntimeConfig:
    """Per-call overrides layered on persisted configuration and the runtime home."""

    home: str | None = None
    msb_path: str | None = None
    libkrunfw_path: str | None = None


@dataclass(frozen=True)
class InstallOptions:
    """Acquisition options, ignored by ensure_runtime when a pair already resolves."""

    source: Literal["release_download", "archive", "directory", "embedded_archive"] = (
        "release_download"
    )
    source_path: str | None = None
    version: str | None = None
    force: bool = False
    verify: bool = True
    expected_archive_sha256: str | None = None


@dataclass(frozen=True)
class ResolvedRuntime:
    """The selected executable, matching firmware library, and resolution source."""

    msb_path: str
    libkrunfw_path: str
    origin: RuntimeOrigin


def _config_json(config: RuntimeConfig | None) -> str:
    return json.dumps(asdict(config or RuntimeConfig()))


def _options_json(options: InstallOptions | None) -> str:
    return json.dumps(asdict(options or InstallOptions()))


def resolve_runtime(config: RuntimeConfig | None = None) -> ResolvedRuntime:
    """Resolve without installing host binaries; raise if absent or incomplete."""
    return ResolvedRuntime(**json.loads(native.resolve_runtime(_config_json(config))))


def is_runtime_installed(config: RuntimeConfig | None = None) -> bool:
    """Return whether a complete pair resolves, including overrides and wheel fallbacks."""
    return native.is_runtime_installed(_config_json(config))


async def install_runtime(
    config: RuntimeConfig | None = None,
    options: InstallOptions | None = None,
) -> ResolvedRuntime:
    """Install from the selected source and return the installed pair."""
    result = await native.install_runtime(_config_json(config), _options_json(options))
    return ResolvedRuntime(**json.loads(result))


async def ensure_runtime(
    config: RuntimeConfig | None = None,
    options: InstallOptions | None = None,
) -> ResolvedRuntime:
    """Resolve first; install only when absent, propagating incomplete-pair errors."""
    result = await native.ensure_runtime(_config_json(config), _options_json(options))
    return ResolvedRuntime(**json.loads(result))
