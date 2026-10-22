"""Guard against false passes in full-resume policy qualification."""

import importlib.util
from pathlib import Path
import socket
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "resume_policy", Path(__file__).with_name("snapshot-resume-policy.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class EvidenceTests(unittest.TestCase):
    def test_immutability_covers_extensionless_objects_and_raw_disks(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            payloads = ["member/checkpoint/objects/sha256/ab/abcdef",
                        "member/checkpoint/layers/root.raw",
                        "member/checkpoint/layers/child.qcow2"]
            for name in payloads:
                path = group / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"original")
            before = smoke.sealed_full(group)
            self.assertEqual(set(before), set(payloads))
            for name in payloads:
                path = group / name
                path.write_bytes(b"changed")
                self.assertNotEqual(smoke.sealed_full(group), before)
                path.write_bytes(b"original")
            (group / ".msb-leases").mkdir()
            (group / ".msb-leases/new.lock").touch()
            (group / ".group.lock").touch()
            self.assertEqual(smoke.sealed_full(group), before)

    def test_allow_requires_an_authenticated_http_request(self):
        for observations in ([], [{"http": False, "authenticated": True}],
                             [{"http": True, "authenticated": False}]):
            with self.assertRaises(RuntimeError):
                smoke.assert_policy("allow", observations)
        with self.assertRaises(RuntimeError):
            smoke.assert_policy("allow", [{"http": True, "authenticated": True,
                                           "authentication": "not-required"}])
        smoke.assert_policy("allow", [{"http": True, "authenticated": True,
                                        "authentication": "accepted"}])

    def test_denial_cannot_pass_after_contact_or_response(self):
        for label in ("deny", "missing-credential"):
            smoke.assert_policy(label, [])
            for observations in ([{"http": False, "authenticated": False}],
                                 [{"http": True, "authenticated": True}]):
                with self.assertRaises(RuntimeError):
                    smoke.assert_policy(label, observations)

    def test_new_protocol_controls_require_real_http_with_correct_handshake(self):
        for label in ("http-connect", "socks4", "socks4-user"):
            expected = "not-required" if label == "http-connect" else "accepted"
            with self.subTest(protocol=label):
                for observations in ([], [{"http": False, "authenticated": True}],
                                     [{"http": True, "authenticated": False}],
                                     [{"http": True, "authenticated": True, "authentication": "rejected"}]):
                    with self.assertRaises(RuntimeError):
                        smoke.assert_policy(label, observations)
                smoke.assert_policy(label, [{"http": True, "authenticated": True,
                                             "authentication": expected}])

    def test_wrong_credentials_require_observed_rejection(self):
        with self.assertRaises(RuntimeError):
            smoke.assert_policy("wrong-credential", [])
        with self.assertRaises(RuntimeError):
            smoke.assert_policy("wrong-credential", [{"http": True, "authenticated": True}])
        with self.assertRaises(RuntimeError):
            smoke.assert_policy("wrong-credential", [{"http": False, "authenticated": False,
                                                      "authentication": "not-attempted"}])
        smoke.assert_policy("wrong-credential", [{"http": False, "authenticated": False,
                                                  "authentication": "rejected"}])

    def test_idle_wait_includes_unfinished_daemon_handlers(self):
        server = smoke.TrackedSocksFixture()
        self.addCleanup(server.close)
        connection = socket.create_connection(server.server_address, timeout=3)
        self.addCleanup(connection.close)
        smoke.wait_until(lambda: not server.idle(), "handler did not start", timeout=3)
        self.assertEqual(smoke.events(server), [])
        connection.close()
        smoke.wait_until(server.idle, "handler did not finish", timeout=3)
        self.assertEqual(len(smoke.events(server)), 1)

    def test_close_records_late_handshake_contact_before_negative_assertion(self):
        server = smoke.TrackedSocksFixture(b"expected")
        self.addCleanup(server.close)
        connection = socket.create_connection(server.server_address, timeout=3)
        self.addCleanup(connection.close)
        smoke.wait_until(lambda: not server.idle(), "handler did not start", timeout=3)
        self.assertEqual(smoke.events(server), [])
        server.close()
        self.assertTrue(server.idle())
        observed = smoke.events(server)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["authentication"], "not-attempted")
        for label in ("deny", "missing-credential", "wrong-credential"):
            with self.assertRaises(RuntimeError):
                smoke.assert_policy(label, observed)


if __name__ == "__main__":
    unittest.main()
