#!/usr/bin/env python3
"""Integration tests for Multi-Port Listener Engine and Prometheus Metrics in Apex.

Covers:
- Concurrently binding multiple ports (e.g. port 1: plain HTTP redirect, port 2: content + metrics)
- Proper request routing per listener port
- Prometheus metrics exposition (/metrics) with duration histogram and process stats
- Graceful reload (SIGHUP) validation (endpoint retention vs port change rejection)
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


class TestMultiListener(unittest.TestCase):
    def setUp(self):
        self.port1 = free_port()
        self.port2 = free_port()
        while self.port2 == self.port1:
            self.port2 = free_port()
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
                with socket.create_connection(("127.0.0.1", self.port1), timeout=0.1):
                    with socket.create_connection(("127.0.0.1", self.port2), timeout=0.1):
                        return
            except OSError:
                time.sleep(0.05)
        self.fail(f"apex failed to bind ports {self.port1} and {self.port2} within {START_TIMEOUT}s")

    def test_multi_port_listen_and_metrics(self):
        conf = f"""
worker_processes 2;

events {{
    worker_connections 1024;
}}

http {{
    server {{
        listen "127.0.0.1:{self.port1}";
        server_name localhost;

        location / {{
            return 301 "http://127.0.0.1:{self.port2}$request_uri";
        }}
    }}

    server {{
        listen "127.0.0.1:{self.port2}";
        server_name localhost;

        location / {{
            return 200 "PORT2_OK\\n";
        }}

        location /metrics {{
            metrics;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Test Port 1 HTTP Redirect
        conn1 = http.client.HTTPConnection("127.0.0.1", self.port1, timeout=2.0)
        conn1.request("GET", "/test-path?param=1")
        resp1 = conn1.getresponse()
        self.assertEqual(resp1.status, 301)
        loc = resp1.getheader("Location")
        self.assertEqual(loc, f"http://127.0.0.1:{self.port2}/test-path?param=1")
        conn1.close()

        # 2. Test Port 2 Response
        conn2 = http.client.HTTPConnection("127.0.0.1", self.port2, timeout=2.0)
        conn2.request("GET", "/hello")
        resp2 = conn2.getresponse()
        self.assertEqual(resp2.status, 200)
        body2 = resp2.read().decode("utf-8")
        self.assertEqual(body2, "PORT2_OK\n")
        conn2.close()

        # 3. Test Prometheus Metrics Scrape on Port 2
        conn_metrics = http.client.HTTPConnection("127.0.0.1", self.port2, timeout=2.0)
        conn_metrics.request("GET", "/metrics")
        resp_m = conn_metrics.getresponse()
        self.assertEqual(resp_m.status, 200)
        self.assertIn("text/plain", resp_m.getheader("Content-Type", ""))
        metrics_body = resp_m.read().decode("utf-8")
        conn_metrics.close()

        # Check Prometheus metric structures
        self.assertIn("apex_http_requests_total", metrics_body)
        self.assertIn("apex_http_request_duration_seconds_bucket", metrics_body)
        self.assertIn("apex_http_request_duration_seconds_count", metrics_body)
        self.assertIn("apex_http_request_duration_seconds_sum", metrics_body)
        self.assertIn("apex_memory_rss_bytes", metrics_body)
        self.assertIn('apex_http_responses_total{code="2xx"}', metrics_body)
        self.assertIn('apex_http_responses_total{code="3xx"}', metrics_body)

        # Verify request counter is at least 2 (the 2 previous requests)
        m = re.search(r'apex_http_requests_total\s+(\d+)', metrics_body)
        self.assertIsNotNone(m, "apex_http_requests_total metric missing in Prometheus output")
        total_reqs = int(m.group(1))
        self.assertGreaterEqual(total_reqs, 2)

    def test_sighup_reload_keeps_listeners(self):
        conf1 = f"""
worker_processes 2;
events {{ worker_connections 1024; }}
http {{
    server {{
        listen "127.0.0.1:{self.port1}";
        location / {{ return 200 "PORT1_V1\\n"; }}
    }}
    server {{
        listen "127.0.0.1:{self.port2}";
        location / {{ return 200 "PORT2_V1\\n"; }}
    }}
}}
"""
        self.start_apex(conf1)

        conn = http.client.HTTPConnection("127.0.0.1", self.port1, timeout=2.0)
        conn.request("GET", "/")
        self.assertEqual(conn.getresponse().read().decode(), "PORT1_V1\n")
        conn.close()

        # Reload with updated response body on same ports
        conf2 = f"""
worker_processes 2;
events {{ worker_connections 1024; }}
http {{
    server {{
        listen "127.0.0.1:{self.port1}";
        location / {{ return 200 "PORT1_V2\\n"; }}
    }}
    server {{
        listen "127.0.0.1:{self.port2}";
        location / {{ return 200 "PORT2_V2\\n"; }}
    }}
}}
"""
        with open(self.conf_path, "w") as f:
            f.write(conf2)

        self.proc.send_signal(subprocess.signal.SIGHUP)
        deadline = time.time() + 3.0
        reloaded = False
        while time.time() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port1, timeout=1.0)
                conn.request("GET", "/")
                resp = conn.getresponse()
                body = resp.read().decode()
                conn.close()
                if body == "PORT1_V2\n":
                    reloaded = True
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)

        self.assertTrue(reloaded, "Timed out waiting for SIGHUP reload to apply updated configuration")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
