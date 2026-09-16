"""TCP alias compatibility and independent UDP limits."""

import unittest
import warnings

from microsandbox.types import Network, ViolationAction


class ConnectionLimitTests(unittest.TestCase):
    def test_omission_is_not_unlimited(self):
        config = Network()._to_dict()
        for key in ("max_connections", "max_tcp_connections", "max_udp_connections"):
            self.assertNotIn(key, config)
        self.assertEqual(Network(max_udp_connections=0)._to_dict()["max_udp_connections"], 0)

    def test_canonical_tcp_and_udp(self):
        config = Network(max_tcp_connections=0, max_udp_connections=7)._to_dict()
        self.assertEqual(config["max_tcp_connections"], 0)
        self.assertEqual(config["max_udp_connections"], 7)
        self.assertNotIn("max_connections", config)

    def test_limits_preserve_secret_violation_action(self):
        config = Network(
            max_tcp_connections=64, max_udp_connections=0,
            secret_violation_action=ViolationAction.BLOCK_AND_TERMINATE,
        )._to_dict()
        self.assertEqual(config["secret_violation_action"], "block-and-terminate")
        self.assertEqual(config["max_tcp_connections"], 64)
        self.assertEqual(config["max_udp_connections"], 0)

    def test_legacy_tcp_warns_and_preserves_udp(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config = Network(max_connections=0, max_udp_connections=7)._to_dict()
        self.assertEqual(config["max_tcp_connections"], 0)
        self.assertEqual(config["max_udp_connections"], 7)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))

    def test_both_tcp_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            Network(max_connections=0, max_tcp_connections=64)._to_dict()
