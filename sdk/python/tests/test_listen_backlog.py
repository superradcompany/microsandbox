"""Published-port listen backlog configuration."""

import unittest

from microsandbox.types import Network


class ListenBacklogTests(unittest.TestCase):
    def test_omission_keeps_the_runtime_default(self):
        self.assertNotIn("tcp_listen_backlog", Network()._to_dict())

    def test_explicit_backlog_reaches_the_network_config(self):
        config = Network(ports={8080: 80}, tcp_listen_backlog=4096)._to_dict()
        self.assertEqual(config["tcp_listen_backlog"], 4096)
