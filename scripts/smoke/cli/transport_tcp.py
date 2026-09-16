"""Small current-wire-only TCP probe; not an SDK, legacy codec, or transport upgrade client.

Wire sources: protocol/lib/{codec,message,tcp}.rs and agent-client/rust/lib/client.rs.
Omitting BulkOffer deliberately exercises inline TcpData, unlike current SSH forwarding.
"""

import json
import select
import socket
import struct
import threading
import time


MAX_FRAME = 4 * 1024 * 1024


def cbor(value):
    def head(major, number):
        if number < 24:
            return bytes([major * 32 + number])
        for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if number < 1 << (8 * width):
                return bytes([major * 32 + marker]) + number.to_bytes(width, "big")
        raise ValueError("CBOR integer overflow")

    if type(value) is int and value >= 0:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise ValueError(f"unsupported probe CBOR value: {type(value)}")


def uncbor(raw):
    position = 0

    def take(size):
        nonlocal position
        if position + size > len(raw):
            raise ValueError("truncated CBOR")
        value = raw[position:position + size]
        position += size
        return value

    def item(depth=0):
        if depth > 8:
            raise ValueError("CBOR nesting exceeded")
        initial = take(1)[0]
        major, number = initial >> 5, initial & 31
        if number >= 24:
            if number not in (24, 25, 26, 27):
                raise ValueError("indefinite/reserved CBOR is outside the probe contract")
            number = int.from_bytes(take(1 << (number - 24)), "big")
        if major == 0:
            return number
        if major in (2, 3):
            value = take(number)
            return value if major == 2 else value.decode()
        if major == 5 and number <= 32:
            value = {}
            for _ in range(number):
                key, member = item(depth + 1), item(depth + 1)
                if key in value:
                    raise ValueError("duplicate CBOR key")
                value[key] = member
            return value
        raise ValueError("unsupported probe CBOR type")

    value = item()
    if position != len(raw):
        raise ValueError("trailing CBOR bytes")
    return value


def frame(identifier, version, kind, payload):
    flags = 2 if kind == "core.tcp.connect" else 0
    body = struct.pack(">IB", identifier, flags) + cbor(dict(v=version, t=kind, p=cbor(payload)))
    if len(body) > MAX_FRAME:
        raise ValueError("probe frame exceeds protocol limit")
    return struct.pack(">I", len(body)) + body


class InlineTcp:
    def __init__(self, path, port, limit):
        self.limit = limit
        self.cancel = threading.Event()
        self.connected = threading.Event()
        self.error, self.receipt = None, None
        self.wire_sent, self.sent, self.blocked = 0, 0, 0
        self.writer, self.reader = None, None
        self.socket = socket.socket(socket.AF_UNIX)
        try:
            self.socket.settimeout(limit())
            self.socket.connect(str(path))
            self.socket.setblocking(False)
            minimum, maximum = struct.unpack(">II", self.receive(8))
            if not 0 < minimum < maximum:
                raise RuntimeError("probe requires a current relay ID-range handshake")
            _, _, ready = self.message()
            if ready["t"] != "core.ready" or not 4 <= ready["v"] <= 9:
                raise RuntimeError("probe requires known current-wire TCP protocol generation")
            self.identifier, self.version = minimum, ready["v"]
            self.send(frame(minimum, self.version, "core.tcp.connect", {"host": "127.0.0.1", "port": port}))
            self.reader = threading.Thread(target=self.read, daemon=True)
            self.reader.start()
            if not self.connected.wait(limit()) or self.error:
                raise RuntimeError(f"TCP connect failed: {self.error}")
        except BaseException:
            self.close()
            raise

    def receive(self, size):
        data = bytearray()
        deadline = time.monotonic() + self.limit()
        while len(data) < size:
            if self.cancel.is_set() or time.monotonic() >= deadline:
                raise RuntimeError("TCP probe read cancelled or timed out")
            if not select.select([self.socket], [], [], .02)[0]:
                continue
            block = self.socket.recv(size - len(data))
            if not block:
                raise RuntimeError("relay closed before TCP terminal frame")
            data.extend(block)
        return bytes(data)

    def message(self):
        length = struct.unpack(">I", self.receive(4))[0]
        if not 5 <= length <= MAX_FRAME:
            raise RuntimeError(f"invalid probe frame length: {length}")
        raw = self.receive(length)
        identifier, flags = struct.unpack(">IB", raw[:5])
        return identifier, flags, uncbor(raw[5:])

    def send(self, data):
        offset = 0
        deadline = time.monotonic() + self.limit()
        while offset < len(data):
            if self.cancel.is_set() or time.monotonic() >= deadline:
                raise RuntimeError("TCP probe write cancelled or timed out")
            try:
                count = self.socket.send(data[offset:])
                if not count:
                    raise RuntimeError("zero-length TCP probe socket write")
                offset += count
                self.wire_sent += count
            except BlockingIOError:
                self.blocked += 1
                select.select([], [self.socket], [], .02)

    def read(self):
        data, eof = bytearray(), False
        try:
            while True:
                identifier, flags, message = self.message()
                if identifier != self.identifier or flags & 8:
                    raise RuntimeError("unexpected TCP correlation ID or raw-bulk frame")
                kind, payload = message["t"], uncbor(message["p"])
                if kind == "core.tcp.connected" and not self.connected.is_set():
                    self.connected.set()
                elif kind == "core.tcp.data" and self.connected.is_set() and not eof:
                    data.extend(payload["data"])
                    if len(data) > 4096:
                        raise RuntimeError("TCP receipt exceeded bound")
                elif kind == "core.tcp.eof" and not eof:
                    eof = True
                elif kind == "core.tcp.closed" and eof and flags & 1:
                    self.receipt = json.loads(data)
                    return
                else:
                    raise RuntimeError(f"unexpected TCP reply: {kind}: {payload}")
        except Exception as error:
            if not self.cancel.is_set():
                self.error = error
                self.connected.set()

    def feed(self, size, payload):
        self.size = size

        def write():
            try:
                for offset in range(0, size, 65536):
                    block = payload(offset, min(65536, size - offset))
                    self.send(frame(self.identifier, self.version, "core.tcp.data", {"data": block}))
                    self.sent += len(block)
                self.send(frame(self.identifier, self.version, "core.tcp.eof", {}))
            except Exception as error:
                if not self.cancel.is_set():
                    self.error = error

        self.writer = threading.Thread(target=write, daemon=True)
        self.writer.start()

    def await_pressure(self):
        previous, stable = -1, time.monotonic()
        deadline = time.monotonic() + self.limit()
        while time.monotonic() < deadline:
            if self.error:
                raise self.error
            if self.sent == self.size:
                raise RuntimeError("TCP input fit in forwarding queues; increase --tcp-mib")
            if self.wire_sent != previous:
                previous, stable = self.wire_sent, time.monotonic()
            elif self.blocked and time.monotonic() - stable >= .2:
                return dict(payload_bytes_framed=self.sent, wire_bytes_written=self.wire_sent,
                            eagain_count=self.blocked, stable_blocked_seconds=time.monotonic() - stable)
            time.sleep(.01)
        raise RuntimeError("TCP sustained backpressure unproven")

    def finish(self):
        for thread in (self.writer, self.reader):
            thread.join(self.limit())
            if thread.is_alive() or self.error:
                raise RuntimeError(f"TCP stream failed: {self.error or 'deadline exceeded'}")
        return self.receipt

    def close(self):
        self.cancel.set()
        for thread in (self.writer, self.reader):
            if thread:
                thread.join(1)
        self.socket.close()
