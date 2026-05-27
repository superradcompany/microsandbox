"""Regression tests for pull-progress session creation."""

from __future__ import annotations

import pytest

from microsandbox import InvalidConfigError, PullSession, Sandbox


@pytest.mark.asyncio
async def test_create_with_progress_returns_session_outside_tokio_reactor() -> None:
    session = Sandbox.create_with_progress(
        "progress-no-reactor",
        image="/__microsandbox_missing_rootfs__",
    )

    assert isinstance(session, PullSession)

    async with session:
        assert [event async for event in session.progress] == []
        with pytest.raises(InvalidConfigError, match="rootfs bind path does not exist"):
            await session.result()
