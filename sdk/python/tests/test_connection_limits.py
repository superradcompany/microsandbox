"""TCP alias compatibility and independent UDP limits."""

import unittest
import warnings

from microsandbox.types import Network


class ConnectionLimitTests(unittest.TestCase):
    def test_canonical_tcp_and_udp(self):
        config = Network(max_tcp_connections=0, max_udp_connections=7)._to_dict()
        self.assertEqual(config["max_tcp_connections"], 0)
        self.assertEqual(config["max_udp_connections"], 7)
        self.assertNotIn("max_connections", config)

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
