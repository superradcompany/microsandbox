"""Explicit destinations shared by resource collections and returned resources."""

import json
import os

from ._microsandbox import Context


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
    """A remote destination; constructing it never changes default-local routing."""

    def __new__(
        cls,
        *,
        url: str | None = None,
        api_key: str | None = None,
        profile: str | None = None,
        request_timeout_ms: int | None = None,
        user_agent: str | None = None,
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
        return super().__new__(cls, json.dumps(options))

    def __init__(
        self, *, url=None, api_key=None, profile=None, request_timeout_ms=None, user_agent=None
    ):
        pass

    @classmethod
    def with_url(
        cls,
        url: str,
        api_key: str,
        *,
        request_timeout_ms: int | None = None,
        user_agent: str | None = None,
    ) -> "RemoteContext":
        """Select an explicit endpoint while retaining the normal option validation."""
        return cls(
            url=url,
            api_key=api_key,
            request_timeout_ms=request_timeout_ms,
            user_agent=user_agent,
        )

    @classmethod
    def from_profile(cls, name: str) -> "RemoteContext":
        return cls(profile=name)

    @classmethod
    def from_env(cls) -> "RemoteContext":
        return cls(url=os.environ.get("MSB_API_URL"), api_key=os.environ.get("MSB_API_KEY"))
