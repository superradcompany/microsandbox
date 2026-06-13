"""Low-level raw agent client."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TypedDict

from microsandbox._microsandbox import PyAgentClient as _PyAgentClient

FLAG_TERMINAL = 0b0000_0001
FLAG_SESSION_START = 0b0000_0010
FLAG_SHUTDOWN = 0b0000_0100


class RawFrame(TypedDict):
    """Raw protocol frame with a CBOR-encoded body."""

    id: int
    flags: int
    body: bytes


class AgentStream:
    """An open raw agent stream."""

    def __init__(self, native: _PyAgentClient, id: int, handle: int) -> None:
        self._native = native
        self.id = id
        self._handle = handle
        self._closed = False

    async def next(self) -> RawFrame | None:
        if self._closed:
            return None

        frame = await self._native.stream_next(self._handle)
        if frame is None:
            self._closed = True
            return None

        if frame["flags"] & FLAG_TERMINAL:
            self._closed = True

        return frame

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._native.stream_close(self._handle)

    async def __aenter__(self) -> AgentStream:
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        await self.close()
        return False

    def __aiter__(self) -> AsyncIterator[RawFrame]:
        return self

    async def __anext__(self) -> RawFrame:
        frame = await self.next()
        if frame is None:
            raise StopAsyncIteration
        return frame


class AgentClient:
    """Raw transport client for talking to agentd through the sandbox relay socket.

    This corresponds to the raw tier of Rust's ``AgentClient``:
    ``request_raw`` / ``stream_raw`` / ``send_raw``.
    """

    def __init__(self, native: _PyAgentClient) -> None:
        self._native = native

    @classmethod
    async def connect_sandbox(
        cls,
        name: str,
        *,
        timeout: float | None = None,
    ) -> AgentClient:
        """Connect to a running sandbox by name.

        Sandbox names are limited to 128 UTF-8 bytes.
        """
        return cls(await _PyAgentClient.connect_sandbox(name, timeout=timeout))

    @classmethod
    async def connect(
        cls,
        path: str,
        *,
        timeout: float | None = None,
    ) -> AgentClient:
        return cls(await _PyAgentClient.connect(path, timeout=timeout))

    @staticmethod
    def socket_path(name: str) -> str:
        """Resolve a sandbox's agentd relay socket path without connecting.

        Returns the same path :meth:`connect_sandbox` would dial, so a caller
        can talk to agentd over a raw byte transport instead of this frame
        client. The sandbox need not be running. Sandbox names are limited to
        128 UTF-8 bytes.
        """
        return _PyAgentClient.socket_path(name)

    async def request(self, flags: int, body: bytes) -> RawFrame:
        return await self._native.request(flags, body)

    async def stream(self, flags: int, body: bytes) -> AgentStream:
        opened = await self._native.stream_open(flags, body)
        return AgentStream(self._native, opened["id"], opened["handle"])

    async def send(self, id: int, flags: int, body: bytes) -> None:
        await self._native.send(id, flags, body)

    def ready_bytes(self) -> bytes:
        return self._native.ready_bytes()

    async def close(self) -> None:
        await self._native.close()
