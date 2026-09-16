"""VM-free checks for the opt-in current-wire inline TCP checkpoint probe."""

import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest


SPEC = importlib.util.spec_from_file_location("transport_tcp", Path(__file__).with_name("transport_tcp.py"))
TCP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TCP)


class TcpProbeTests(unittest.TestCase):
    def test_cbor_matches_fixed_wire_fixture_and_rejects_ambiguous_values(self):
        self.assertEqual(TCP.cbor({"data": b"abc"}), bytes.fromhex("a1646461746143616263"))
        self.assertEqual(TCP.uncbor(bytes.fromhex("a1646461746143616263")), {"data": b"abc"})
        for value in (0, 23, 24, 255, 256, 65535, 65536, 2 ** 32, "é", b"z" * 65536):
            self.assertEqual(TCP.uncbor(TCP.cbor(value)), value)
        for raw in (b"", b"\xbf\xff", b"\x00\x00", b"\x63x", bytes.fromhex("a2617800617801")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                TCP.uncbor(raw)
        with self.assertRaises(ValueError):
            TCP.cbor(-1)

    def test_connect_frame_omits_bulk_offer_and_uses_session_start_flag(self):
        encoded = TCP.frame(123, 9, "core.tcp.connect", {"host": "127.0.0.1", "port": 32017})
        self.assertEqual(struct.unpack(">I", encoded[:4])[0], len(encoded) - 4)
        self.assertEqual(struct.unpack(">IB", encoded[4:9]), (123, 2))
        envelope = TCP.uncbor(encoded[9:])
        self.assertEqual(envelope["v"], 9)
        self.assertEqual(TCP.uncbor(envelope["p"]), {"host": "127.0.0.1", "port": 32017})
        with self.assertRaises(ValueError):
            TCP.frame(1, 9, "core.tcp.data", {"data": b"x" * TCP.MAX_FRAME})

    def test_bounded_local_relay_saturation_preserves_data_and_tcp_eof(self):
        with tempfile.TemporaryDirectory(prefix="tcp-unit-", dir="/tmp") as directory:
            path = Path(directory) / "agent.sock"
            gate, errors = threading.Event(), []
            listener = socket.socket(socket.AF_UNIX)
            self.addCleanup(listener.close)
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(5)
            payload = bytes(range(256)) * 8192
            expected = dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                            eof=True, eof_kind="pipe-close")

            def relay():
                try:
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(5)

                        def exact(size):
                            data = bytearray()
                            while len(data) < size:
                                block = peer.recv(size - len(data))
                                if not block:
                                    raise RuntimeError("unexpected test client EOF")
                                data.extend(block)
                            return bytes(data)

                        def message():
                            length = struct.unpack(">I", exact(4))[0]
                            raw = exact(length)
                            self.assertEqual(struct.unpack(">I", raw[:4])[0], 11)
                            return TCP.uncbor(raw[5:])

                        peer.sendall(struct.pack(">II", 11, 111) + TCP.frame(0, 9, "core.ready", {}))
                        self.assertEqual(message()["t"], "core.tcp.connect")
                        peer.sendall(TCP.frame(11, 9, "core.tcp.connected", {}))
                        if not gate.wait(5):
                            raise RuntimeError("test gate did not release")
                        received = bytearray()
                        while True:
                            current = message()
                            if current["t"] == "core.tcp.eof":
                                break
                            self.assertEqual(current["t"], "core.tcp.data")
                            received.extend(TCP.uncbor(current["p"])["data"])
                        self.assertEqual(received, payload)
                        terminal = bytearray(TCP.frame(11, 9, "core.tcp.closed", {}))
                        terminal[8] = 1
                        output = (TCP.frame(11, 9, "core.tcp.data", {"data": json.dumps(expected).encode()})
                                  + TCP.frame(11, 9, "core.tcp.eof", {}) + terminal)
                        for offset in range(0, len(output), 7):
                            peer.sendall(output[offset:offset + 7])
                except BaseException as error:
                    # Propagate every worker failure, including SystemExit, to the test thread's
                    # final assertion rather than letting a thread exit look like a passing relay.
                    errors.append(error)

            thread = threading.Thread(target=relay, daemon=True)
            thread.start()
            client = TCP.InlineTcp(path, 32017, lambda: 5)
            try:
                client.feed(len(payload), lambda offset, count: payload[offset:offset + count])
                proof = client.await_pressure()
                self.assertGreater(proof["eagain_count"], 0)
                self.assertLess(proof["payload_bytes_framed"], len(payload))
                gate.set()
                self.assertEqual(client.finish(), expected)
            finally:
                gate.set()
                client.close()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
