"""Published-port TCP accept queue size configuration."""

import unittest

from microsandbox.types import Network


class TcpAcceptQueueSizeTests(unittest.TestCase):
    def test_omission_keeps_the_runtime_default(self):
        self.assertNotIn("tcp_accept_queue_size", Network()._to_dict())

    def test_explicit_size_reaches_the_network_config(self):
        config = Network(ports={8080: 80}, tcp_accept_queue_size=4096)._to_dict()
        self.assertEqual(config["tcp_accept_queue_size"], 4096)
