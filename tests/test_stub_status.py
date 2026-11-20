#!/usr/bin/env python3
"""Integration tests for Observability: stub_status and Prometheus /metrics in Apex.

Covers:
- 100% Nginx-compatible stub_status format
- Active connections, accepts, handled, requests, Reading, Writing, Waiting
- Prometheus exposition format (/metrics)
- Request counting, status code classes (2xx, 3xx, 4xx, 5xx), cache counters
"""

import http.client
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestStubStatus(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.temp_dir.cleanup()

    def start_apex(self, conf_content):
        with open(self.conf_path, "w") as f:
            f.write(conf_content)
        self.proc = subprocess.Popen(
            [APEX, "-c", self.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                _, err = self.proc.communicate()
                self.fail(f"apex exited prematurely: {err.decode('utf-8', errors='replace')}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        self.fail(f"apex failed to bind port {self.port} within {START_TIMEOUT}s")

    def test_01_stub_status_format(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        location /nginx_status {{
            stub_status;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/nginx_status")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "text/plain")
        body = resp.read().decode("utf-8")
        conn.close()

        lines = body.splitlines()
        self.assertEqual(len(lines), 4, f"Expected exactly 4 lines, got {len(lines)}: {body!r}")
        
        # Line 1: Active connections: N 
        self.assertTrue(re.match(r"^Active connections: \d+ $", lines[0]), f"Invalid line 1: {lines[0]!r}")
        
        # Line 2: server accepts handled requests
        self.assertEqual(lines[1], "server accepts handled requests")
        
        # Line 3:  <accepts> <handled> <requests> 
        self.assertTrue(re.match(r"^ \d+ \d+ \d+ $", lines[2]), f"Invalid line 3: {lines[2]!r}")
        
        # Line 4: Reading: N Writing: N Waiting: N 
        self.assertTrue(re.match(r"^Reading: \d+ Writing: \d+ Waiting: \d+ $", lines[3]), f"Invalid line 4: {lines[3]!r}")

    def test_02_stub_status_counter_increments(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        location /nginx_status {{
            stub_status;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # Make 5 requests and verify request counter increases
        prev_requests = 0
        for i in range(5):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/nginx_status")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            conn.close()
            
            lines = body.splitlines()
            parts = lines[2].strip().split()
            accepts, handled, requests = int(parts[0]), int(parts[1]), int(parts[2])
            self.assertGreaterEqual(accepts, 1)
            self.assertGreaterEqual(handled, 1)
            self.assertGreater(requests, prev_requests)
            prev_requests = requests

    def test_03_prometheus_metrics_format(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        location /metrics {{
            metrics;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertTrue("text/plain" in resp.getheader("Content-Type"))
        self.assertTrue("version=0.0.4" in resp.getheader("Content-Type"))
        body = resp.read().decode("utf-8")
        conn.close()

        required_metrics = [
            "apex_connections_active",
            "apex_connections_reading",
            "apex_connections_writing",
            "apex_connections_waiting",
            "apex_connections_accepted_total",
            "apex_connections_handled_total",
            "apex_http_requests_total",
            'apex_http_responses_total{code="2xx"}',
            'apex_http_responses_total{code="3xx"}',
            'apex_http_responses_total{code="4xx"}',
            'apex_http_responses_total{code="5xx"}',
            'apex_cache_requests_total{status="hit"}',
            'apex_cache_requests_total{status="miss"}',
            'apex_cache_requests_total{status="bypass"}',
        ]

        for metric in required_metrics:
            self.assertIn(metric, body, f"Metric '{metric}' not found in /metrics output")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
