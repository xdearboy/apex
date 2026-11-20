#!/usr/bin/env python3
"""Integration tests for dynamic DNS resolver and cache in Apex.

Covers:
- Dynamic upstream resolution via custom UDP DNS server
- DNS cache hit avoiding repeated queries within valid TTL
- DNS cache expiration and re-resolution
- resolver and resolver_timeout directive parsing and inheritance
"""

import http.server
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = os.path.abspath("./apex")
for arg in sys.argv[1:]:
    if not arg.startswith("-") and os.path.isfile(arg):
        APEX = os.path.abspath(arg)
        break

START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockDNSServer:
    """Lightweight RFC 1035 UDP DNS server for integration testing."""

    def __init__(self, ip_to_return="127.0.0.1", ttl=1):
        self.ip_to_return = ip_to_return
        self.ttl = ttl
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.query_count = 0
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.sock.settimeout(0.2)
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            self.query_count += 1
            if len(data) < 12:
                continue

            # Parse query header
            qid = data[:2]
            # Standard query response flags: 0x8180 (response, recursion desired, recursion available, no error)
            flags = b"\x81\x80"
            qdcount = data[4:6]
            ancount = b"\x00\x01"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"

            # Skip QNAME in question section
            offset = 12
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            if offset < len(data) and data[offset] == 0:
                offset += 1
            offset += 4  # QTYPE + QCLASS
            question = data[12:offset]

            # Construct Answer: pointer to QNAME (0xc00c), TYPE A (0x0001), CLASS IN (0x0001), TTL, RDLENGTH 4, IP
            ans_name = b"\xc0\x0c"
            ans_type = b"\x00\x01"
            ans_class = b"\x00\x01"
            ans_ttl = struct.pack(">I", self.ttl)
            ans_rdlen = b"\x00\x04"
            ip_parts = [int(p) for p in self.ip_to_return.split(".")]
            ans_rdata = bytes(ip_parts)

            answer = ans_name + ans_type + ans_class + ans_ttl + ans_rdlen + ans_rdata
            response = qid + flags + qdcount + ancount + nscount + arcount + question + answer
            self.sock.sendto(response, addr)

    def stop(self):
        self.running = False
        self.sock.close()
        self.thread.join(timeout=1.0)


class SimpleEchoBackend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"backend-port-{self.server.server_address[1]}".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestDynamicDNSResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_port1 = free_port()
        cls.backend_port2 = free_port()
        cls.dns_server = MockDNSServer(ip_to_return="127.0.0.1", ttl=1)
        cls.apex_port = free_port()

        cls.httpd1 = http.server.HTTPServer(("127.0.0.1", cls.backend_port1), SimpleEchoBackend)
        cls.thread1 = threading.Thread(target=cls.httpd1.serve_forever, daemon=True)
        cls.thread1.start()

        cls.httpd2 = http.server.HTTPServer(("127.0.0.1", cls.backend_port2), SimpleEchoBackend)
        cls.thread2 = threading.Thread(target=cls.httpd2.serve_forever, daemon=True)
        cls.thread2.start()

        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(f"""
http {{
    worker_connections 256;
    resolver 127.0.0.1:{cls.dns_server.port} valid=1s;
    resolver_timeout 2s;

    server {{
        listen {cls.apex_port};

        location /dyn/ {{
            proxy_pass http://$http_host:{cls.backend_port1};
        }}
    }}
}}
""")
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.apex_port), timeout=0.2):
                    started = True
                    break
            except OSError:
                time.sleep(0.05)
        if not started:
            cls.proc.kill()
            raise RuntimeError("Apex failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.httpd1.shutdown()
        cls.httpd2.shutdown()
        cls.dns_server.stop()
        os.unlink(cls.conf_file.name)

    def _get(self, path, host):
        with socket.create_connection(("127.0.0.1", self.apex_port), timeout=3.0) as sock:
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode("utf-8"))
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            return resp

    def test_01_dns_resolution_and_cache(self):
        """Test initial DNS resolution and caching within TTL."""
        initial_queries = self.dns_server.query_count
        resp1 = self._get("/dyn/test", "dynbackend.local")
        self.assertIn(b"200 OK", resp1)
        self.assertIn(f"backend-port-{self.backend_port1}".encode("utf-8"), resp1)
        self.assertGreater(self.dns_server.query_count, initial_queries)

        queries_after_first = self.dns_server.query_count

        # Second request should hit DNS cache (no additional DNS query)
        resp2 = self._get("/dyn/test", "dynbackend.local")
        self.assertIn(b"200 OK", resp2)
        self.assertEqual(self.dns_server.query_count, queries_after_first)

    def test_02_dns_cache_expiration(self):
        """Test that after valid TTL expires, DNS query is performed again."""
        resp1 = self._get("/dyn/test", "expiring.local")
        self.assertIn(b"200 OK", resp1)
        count_before = self.dns_server.query_count

        # Wait for valid=1s to expire
        time.sleep(1.2)

        resp2 = self._get("/dyn/test", "expiring.local")
        self.assertIn(b"200 OK", resp2)
        # Should have re-queried DNS
        self.assertGreater(self.dns_server.query_count, count_before)


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
