#!/usr/bin/env python3
"""Integration tests for Active Upstream Health Checking (health_check) in Apex.

Covers:
- Background prober worker probing upstream servers on configured interval
- Detecting failed backends and marking them unhealthy (consecutive failures >= fall)
- Seamless failover: all client traffic routed to remaining healthy backends with 0 errors
- Automatic recovery: once failed backend resumes responding 200 OK, restored to rotation (consecutive successes >= rise)
"""

import http.client
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RespondingBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"node:{self.server.node_name}".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class ControllableBackend:
    def __init__(self, node_name):
        self.node_name = node_name
        self.port = free_port()
        self.server = None
        self.thread = None
        self.start()

    def start(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), RespondingBackendHandler)
        self.server.node_name = self.node_name
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


class TestHealthCheck(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None
        self.backend_a = ControllableBackend("backend_a")
        self.backend_b = ControllableBackend("backend_b")

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.backend_a.stop()
        self.backend_b.stop()
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

    def query(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)
        conn.request("GET", "/test")
        resp = conn.getresponse()
        status = resp.status
        body = resp.read().decode("utf-8")
        conn.close()
        return status, body

    def test_01_active_failover_and_recovery(self):
        conf = f"""
http {{
    upstream test_pool {{
        server 127.0.0.1:{self.backend_a.port};
        server 127.0.0.1:{self.backend_b.port};
        health_check uri=/health interval=200ms timeout=200ms fall=2 rise=2;
    }}

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location / {{
            proxy_pass http://test_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Initially both backends respond
        seen = set()
        for _ in range(6):
            status, body = self.query()
            self.assertEqual(status, 200)
            seen.add(body)
        self.assertIn("node:backend_a", seen)
        self.assertIn("node:backend_b", seen)

        # 2. Stop backend A
        self.backend_a.stop()

        # Wait for prober to detect failure (interval 200ms * 2 fall = 400ms + buffer)
        time.sleep(0.8)

        # Verify all subsequent requests only go to backend B without any errors
        for _ in range(10):
            status, body = self.query()
            self.assertEqual(status, 200)
            self.assertEqual(body, "node:backend_b")

        # 3. Restart backend A
        self.backend_a.start()

        # Wait for prober to detect recovery (interval 200ms * 2 rise = 400ms + buffer)
        time.sleep(0.8)

        # Verify traffic returns to both backends
        seen_after = set()
        for _ in range(10):
            status, body = self.query()
            self.assertEqual(status, 200)
            seen_after.add(body)
        self.assertIn("node:backend_a", seen_after)
        self.assertIn("node:backend_b", seen_after)


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
