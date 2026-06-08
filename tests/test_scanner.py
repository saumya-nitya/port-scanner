"""
Unit tests for port_scanner.py
Run with: python -m pytest tests/ -v
"""

import sys
import os
import socket
import threading
import unittest
from queue import Queue
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import port_scanner


class TestResolveTarget(unittest.TestCase):

    def test_valid_ip_passthrough(self):
        result = port_scanner.resolve_target("127.0.0.1")
        self.assertEqual(result, "127.0.0.1")

    def test_localhost_resolves(self):
        result = port_scanner.resolve_target("localhost")
        self.assertIn(result, ["127.0.0.1", "::1"])

    def test_invalid_hostname_exits(self):
        with self.assertRaises(SystemExit):
            port_scanner.resolve_target("this.hostname.does.not.exist.invalid")


class TestScanPort(unittest.TestCase):

    def setUp(self):
        port_scanner.open_ports.clear()

    def test_open_port_detected(self):
        """Spin up a real TCP listener and confirm the scanner finds it."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        try:
            port_scanner.scan_port("127.0.0.1", port, timeout=1.0, grab_banners=False)
            ports_found = [p[0] for p in port_scanner.open_ports]
            self.assertIn(port, ports_found)
        finally:
            server.close()

    def test_closed_port_not_recorded(self):
        """A port with no listener should not appear in results."""
        # Port 1 is almost certainly closed/refused on any test machine
        port_scanner.scan_port("127.0.0.1", 1, timeout=0.2, grab_banners=False)
        ports_found = [p[0] for p in port_scanner.open_ports]
        self.assertNotIn(1, ports_found)

    def test_known_service_name(self):
        """Open port 80 equivalent should map to HTTP if in COMMON_PORTS."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        # Temporarily register the port as a known service
        port_scanner.COMMON_PORTS[port] = "TEST-SERVICE"
        try:
            port_scanner.scan_port("127.0.0.1", port, timeout=1.0, grab_banners=False)
            services = {p[0]: p[1] for p in port_scanner.open_ports}
            self.assertEqual(services.get(port), "TEST-SERVICE")
        finally:
            server.close()
            del port_scanner.COMMON_PORTS[port]


class TestWorkerQueue(unittest.TestCase):

    def setUp(self):
        port_scanner.open_ports.clear()

    def test_queue_fully_consumed(self):
        """Worker threads should drain the queue completely."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        open_port = server.getsockname()[1]

        q = Queue()
        for p in [open_port, 1, 2, 3]:
            q.put(p)

        t = threading.Thread(
            target=port_scanner.worker,
            args=("127.0.0.1", q, 0.3, False)
        )
        t.start()
        t.join(timeout=5)

        self.assertTrue(q.empty())
        server.close()


class TestCommonPorts(unittest.TestCase):

    def test_common_ports_not_empty(self):
        self.assertGreater(len(port_scanner.COMMON_PORTS), 0)

    def test_well_known_entries(self):
        self.assertEqual(port_scanner.COMMON_PORTS[22], "SSH")
        self.assertEqual(port_scanner.COMMON_PORTS[80], "HTTP")
        self.assertEqual(port_scanner.COMMON_PORTS[443], "HTTPS")


if __name__ == "__main__":
    unittest.main()
