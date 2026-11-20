"""Ensure proxy qualification records real traffic without retaining credentials."""

import importlib.util
import json
from pathlib import Path
import socket
import struct
import threading
import time
import unittest


spec = importlib.util.spec_from_file_location(
    "snapshot_launch_proxy", Path(__file__).with_name("snapshot-launch-proxy.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class ProxyFixtureTests(unittest.TestCase):
    def server(self, password=None):
        server = smoke.SocksFixture(password)
        self.addCleanup(server.close)
        return server

    def connect(self, server):
        stream = socket.create_connection(server.server_address, timeout=3)
        self.addCleanup(stream.close)
        return stream

    def events(self, server):
        deadline = time.monotonic() + 5
        while not server.events and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(server.events, "fixture failed to finish its connection")
        return server.events

    def request(self, stream, target=smoke.TARGET):
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target)
                       + struct.pack("!H", smoke.TARGET_PORT))
        self.assertEqual(smoke.receive(stream, 10)[1], 0)
        stream.sendall(b"GET /probe HTTP/1.1\r\nHost: fixture\r\n\r\n")
        response = b""
        while chunk := stream.recv(4096):
            response += chunk
        self.assertTrue(response.endswith(smoke.BODY))

    def test_plain_guest_request_is_observed(self):
        server = self.server()
        stream = self.connect(server)
        stream.sendall(b"\x05\x01\x00")
        self.assertEqual(smoke.receive(stream, 2), b"\x05\x00")
        self.request(stream)
        self.assertEqual(self.events(server), [{
            "authenticated": True, "authentication": "not-required",
            "target": [smoke.TARGET, smoke.TARGET_PORT], "http": True}])

    def test_authenticated_request_records_no_credential_material(self):
        server = self.server(b"sensitive-test-value")
        stream = self.connect(server)
        stream.sendall(b"\x05\x02\x00\x02")
        self.assertEqual(smoke.receive(stream, 2), b"\x05\x02")
        stream.sendall(b"\x01\x07fixture\x14sensitive-test-value")
        self.assertEqual(smoke.receive(stream, 2), b"\x01\x00")
        self.request(stream)
        encoded = json.dumps(self.events(server))
        self.assertNotIn("sensitive-test-value", encoded)
        self.assertNotIn("fixture", encoded)
        self.assertTrue(server.events[0]["http"])

    def test_wrong_password_never_receives_http_success(self):
        server = self.server(b"correct")
        stream = self.connect(server)
        stream.sendall(b"\x05\x01\x02")
        self.assertEqual(smoke.receive(stream, 2), b"\x05\x02")
        stream.sendall(b"\x01\x07fixture\x05wrong")
        self.assertEqual(smoke.receive(stream, 2), b"\x01\x01")
        self.assertEqual(self.events(server), [{
            "authenticated": False, "authentication": "rejected", "target": None, "http": False}])

    def test_unexpected_target_is_not_a_compatibility_pass(self):
        server = self.server()
        stream = self.connect(server)
        stream.sendall(b"\x05\x01\x00")
        smoke.receive(stream, 2)
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("198.51.100.99")
                       + struct.pack("!H", smoke.TARGET_PORT))
        self.assertEqual(stream.recv(10), b"")
        event = self.events(server)[0]
        self.assertFalse(event["http"])
        self.assertEqual(event["error"], "ValueError")

    def test_receive_handles_partial_transport_reads(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        def send():
            for part in (b"a", b"b", b"c"):
                right.sendall(part)
                time.sleep(0.01)
            right.close()
        writer = threading.Thread(target=send)
        writer.start()
        try:
            self.assertEqual(smoke.receive(left, 3), b"abc")
            with self.assertRaises(EOFError):
                smoke.receive(left, 1)
        finally:
            writer.join(timeout=3)
        self.assertFalse(writer.is_alive())

    def tunneled_http(self, stream):
        stream.sendall(b"GET /probe HTTP/1.1\r\nHost: fixture\r\n\r\n")
        response = b""
        while chunk := stream.recv(4096):
            response += chunk
        self.assertTrue(response.endswith(smoke.BODY))

    def test_http_connect_serves_only_the_expected_tunnel(self):
        server = smoke.HttpFixture()
        self.addCleanup(server.close)
        stream = self.connect(server)
        stream.sendall(f"CONNECT {smoke.TARGET}:{smoke.TARGET_PORT} HTTP/1.1\r\nHost: private-header\r\n\r\n".encode())
        self.assertTrue(smoke.read_headers(stream).startswith(b"HTTP/1.1 200"))
        self.tunneled_http(stream)
        events = self.events(server)
        self.assertTrue(events[0]["http"])
        self.assertNotIn("private-header", json.dumps(events))

    def test_http_connect_rejects_other_destinations(self):
        server = smoke.HttpFixture()
        self.addCleanup(server.close)
        stream = self.connect(server)
        stream.sendall(b"CONNECT unrelated.invalid:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(stream.recv(10), b"")
        self.assertFalse(self.events(server)[0]["http"])

    def test_socks4_accepts_explicit_or_empty_user_without_recording_it(self):
        for user in (b"", b"private-user-value"):
            with self.subTest(has_user=bool(user)):
                server = smoke.Socks4Fixture(user or None)
                self.addCleanup(server.close)
                stream = self.connect(server)
                stream.sendall(struct.pack("!BBH4s", 4, 1, smoke.TARGET_PORT,
                                           socket.inet_aton(smoke.TARGET)) + user + b"\0")
                self.assertEqual(smoke.receive(stream, 8)[1], 90)
                self.tunneled_http(stream)
                events = self.events(server)
                self.assertTrue(events[0]["http"])
                self.assertNotIn("private-user-value", json.dumps(events))

    def test_socks4_wrong_user_cannot_receive_http_success(self):
        server = smoke.Socks4Fixture(b"expected-user")
        self.addCleanup(server.close)
        stream = self.connect(server)
        stream.sendall(struct.pack("!BBH4s", 4, 1, smoke.TARGET_PORT,
                                   socket.inet_aton(smoke.TARGET)) + b"wrong-user\0")
        self.assertEqual(smoke.receive(stream, 8)[1], 91)
        events = self.events(server)
        self.assertEqual(events[0]["authentication"], "rejected")
        self.assertFalse(events[0]["http"])
        self.assertNotIn("user", json.dumps(events))

    def test_headers_and_socks4_user_are_bounded(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(b"x" * 8192)
        with self.assertRaises(ValueError):
            smoke.read_headers(right)
        server = smoke.Socks4Fixture()
        self.addCleanup(server.close)
        stream = self.connect(server)
        stream.sendall(struct.pack("!BBH4s", 4, 1, smoke.TARGET_PORT,
                                   socket.inet_aton(smoke.TARGET)) + b"x" * 256)
        self.assertEqual(stream.recv(10), b"")
        self.assertFalse(self.events(server)[0]["http"])


class DnsFixtureTests(unittest.TestCase):
    def query(self, name=smoke.DNS_NAME, kind=1):
        labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
        return struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", kind, 1)

    def test_dns_fixture_supplies_the_reserved_target_without_forwarding(self):
        response, kind = smoke.dns_response(self.query())
        self.assertEqual(kind, 1)
        self.assertEqual(response[:2], struct.pack("!H", 123))
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
        self.assertEqual(socket.inet_ntoa(response[-4:]), smoke.TARGET)

    def test_ipv6_question_returns_no_invented_ipv6_address(self):
        response, kind = smoke.dns_response(self.query(kind=28))
        self.assertEqual(kind, 28)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)

    def test_foreign_name_or_multiple_questions_are_rejected(self):
        with self.assertRaises(ValueError):
            smoke.dns_response(self.query(name="unrelated.example"))
        invalid = bytearray(self.query())
        invalid[5] = 2
        with self.assertRaises(ValueError):
            smoke.dns_response(invalid)


if __name__ == "__main__":
    unittest.main()
