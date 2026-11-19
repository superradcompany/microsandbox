"""Explicit destinations shared by resource collections and returned resources."""

import json
import os
from typing import Literal

from ._microsandbox import Context
from .types import ComputeType


class LocalContext(Context):
    """Capture local configuration without starting a runtime or opening its catalog."""

    def __new__(
        cls,
        *,
        home: str | os.PathLike[str] | None = None,
        config_path: str | os.PathLike[str] | None = None,
    ):
        options = {"kind": "local"}
        if home is not None:
            options["home"] = os.fspath(home)
        if config_path is not None:
            options["configPath"] = os.fspath(config_path)
        return super().__new__(cls, json.dumps(options))

    def __init__(self, *, home=None, config_path=None):
        # Native __new__ has already captured immutable shared configuration.
        pass


class RemoteContext(Context):
    """A remote destination; constructing it preserves the configured default."""

    def __new__(
        cls,
        *,
        url: str | None = None,
        api_key: str | None = None,
        profile: str | None = None,
        request_timeout_ms: int | None = None,
        user_agent: str | None = None,
        compute_type: ComputeType | Literal["standard", "shared"] | None = None,
    ):
        if request_timeout_ms is not None and (
            isinstance(request_timeout_ms, bool)
            or not isinstance(request_timeout_ms, int)
            or not 0 <= request_timeout_ms < 2**64
        ):
            raise ValueError("request_timeout_ms must be a non-negative 64-bit integer")
        options = {
            "kind": "remote",
            "url": url,
            "apiKey": api_key,
            "profile": profile,
            "requestTimeoutMs": request_timeout_ms,
            "userAgent": user_agent,
        }
        if compute_type is not None:
            options["computeType"] = compute_type
        return super().__new__(cls, json.dumps(options))

    def __init__(
        self,
        *,
        url=None,
        api_key=None,
        profile=None,
        request_timeout_ms=None,
        user_agent=None,
        compute_type=None,
    ):
        pass

    def replace(
        self,
        *,
        url: str | None = None,
        api_key: str | None = None,
        request_timeout_ms: int | None = None,
        user_agent: str | None = None,
        compute_type: ComputeType | Literal["standard", "shared"] | None = None,
    ) -> "RemoteContext":
        """Return an independent context with overrides; None retains the captured value.

        Profiles, environment and configuration files are not read again. Existing
        resources and this context retain their destination and credentials.
        """
        if request_timeout_ms is not None and (
            isinstance(request_timeout_ms, bool)
            or not isinstance(request_timeout_ms, int)
            or not 0 <= request_timeout_ms < 2**64
        ):
            raise ValueError("request_timeout_ms must be a non-negative 64-bit integer")
        options = {
            "url": url,
            "apiKey": api_key,
            "requestTimeoutMs": request_timeout_ms,
            "userAgent": user_agent,
        }
        if compute_type is not None:
            options["computeType"] = compute_type
        # Allocate the concrete wrapper around derived native state, without rerunning
        # the public constructor or copying credentials into Python.
        return Context.__new__(type(self), json.dumps(options), self)

    @classmethod
    def with_url(
        cls,
        url: str,
        api_key: str,
        *,
        request_timeout_ms: int | None = None,
        user_agent: str | None = None,
        compute_type: ComputeType | Literal["standard", "shared"] | None = None,
    ) -> "RemoteContext":
        """Select an explicit endpoint while retaining the normal option validation."""
        return cls(
            url=url,
            api_key=api_key,
            request_timeout_ms=request_timeout_ms,
            user_agent=user_agent,
            compute_type=compute_type,
        )

    @classmethod
    def from_profile(cls, name: str) -> "RemoteContext":
        return cls(profile=name)

    @classmethod
    def from_env(cls) -> "RemoteContext":
        return cls()
