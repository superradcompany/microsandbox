"""Regression tests for pull-progress session creation."""

from __future__ import annotations

import asyncio

import pytest

from microsandbox import (
    CloudHttpError,
    InvalidConfigError,
    LocalContext,
    PullSession,
    RemoteContext,
    Sandbox,
)


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


@pytest.mark.asyncio
@pytest.mark.parametrize("read_progress", [False, True])
async def test_unclaimed_create_error_surfaces_at_scope_exit(read_progress):
    session = Sandbox.create_with_progress(
        "progress-error", image="/__microsandbox_missing_rootfs__",
    )
    with pytest.raises(InvalidConfigError, match="rootfs bind path does not exist"):
        async with session:
            if read_progress:
                assert [event async for event in session.progress] == []
    with pytest.raises(RuntimeError, match="already consumed"):
        await session.result()


@pytest.mark.asyncio
async def test_scope_exit_preserves_body_exception():
    session = Sandbox.create_with_progress(
        "progress-body", image="/__microsandbox_missing_rootfs__",
    )
    failure = ValueError("body failed")
    body_result = asyncio.get_running_loop().create_future()
    body_result.set_exception(failure)
    with pytest.raises(ValueError) as caught:
        async with session:
            await body_result
    assert caught.value is failure


@pytest.mark.asyncio
async def test_context_bound_restore_reports_unclaimed_failure(tmp_path):
    session = LocalContext().sandboxes.restore_with_progress(
        tmp_path / "missing", name="progress-restore",
    )
    with pytest.raises(FileNotFoundError):
        async with session:
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_creation", [False, True])
async def test_cancellation_while_remote_creation_is_pending(cancel_creation):
    # Hold the provider response until the observer or the creation task has been cancelled.
    requested = asyncio.Event()
    release = asyncio.Event()
    disconnected = asyncio.Event()

    async def respond(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            requested.set()
            await release.wait()
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()
            disconnected.set()

    async with await asyncio.start_server(respond, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        remote = RemoteContext.with_url(f"http://127.0.0.1:{port}", "test-key")
        session = remote.sandboxes.create_with_progress("progress-cancel", image="alpine")
        try:
            observer = session.result()
            await asyncio.wait_for(requested.wait(), timeout=5)
            if cancel_creation:
                session.cancel()
                with pytest.raises(RuntimeError, match="cancelled"):
                    await asyncio.wait_for(observer, timeout=5)
            else:
                observer.cancel()
                with pytest.raises(asyncio.CancelledError):
                    _ = await observer
                release.set()
                with pytest.raises(CloudHttpError, match="403"):
                    await asyncio.wait_for(session.result(), timeout=5)
        finally:
            release.set()
            if requested.is_set():
                await asyncio.wait_for(disconnected.wait(), timeout=5)
