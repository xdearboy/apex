#!/usr/bin/env python3
"""Integration tests for Rate Limiting & Concurrency Limiting in Apex.

Covers:
- limit_req_zone and limit_req directives
- Token bucket burst and nodelay behavior
- 429 and 503 rejection status codes
- Retry-After header injection
- limit_conn_zone and limit_conn concurrency throttling
"""

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


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if "/slow" in self.path:
            time.sleep(0.4)
        body = b"backend-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class RawHttpClient:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, host="127.0.0.1"):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))

        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()

        parts = raw.split(b"\r\n\r\n", 1)
        headers_raw = parts[0].decode("utf-8", "replace")
        body = parts[1] if len(parts) > 1 else b""
        lines = headers_raw.split("\r\n")
        status_code = int(lines[0].split(" ")[1])

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status_code, headers, body.decode("utf-8", "replace")


class RateLimitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_server, cls.backend_port = start_backend()
        cls.port = free_port()

        cls.workdir = tempfile.mkdtemp(prefix="apex_test_ratelimit_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    limit_req_zone $remote_addr zone=api_zone:10m rate=2r/s;
    limit_req_zone $remote_addr zone=strict_zone:10m rate=1r/s;
    limit_conn_zone $remote_addr zone=conn_zone:10m;

    upstream backend_pool {{
        server 127.0.0.1:{cls.backend_port};
    }}

    server {{
        listen 127.0.0.1:{cls.port};
        server_name localhost;

        location /api {{
            limit_req zone=api_zone burst=2 nodelay;
            limit_req_status 429;
            proxy_pass http://backend_pool;
        }}

        location /strict {{
            limit_req zone=strict_zone;
            limit_req_status 503;
            proxy_pass http://backend_pool;
        }}

        location /conn {{
            limit_conn conn_zone 1;
            limit_conn_status 429;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        with open(cls.conf_path, "w") as f:
            f.write(config)

        cls.proc = subprocess.Popen(
            [APEX, "-c", cls.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    started = True
                    break
            except OSError:
                time.sleep(0.05)

        if not started:
            cls.proc.kill()
            out, err = cls.proc.communicate()
            raise RuntimeError(f"Apex failed to start: {err.decode('utf-8', 'replace')}")

        cls.client = RawHttpClient(cls.port)

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()
        cls.backend_server.shutdown()

    def test_burst_and_rate_limit_exceeded(self):
        # rate=2r/s, burst=2 -> capacity is 3 requests
        statuses = []
        retry_after = None
        for _ in range(5):
            status, headers, body = self.client.request("GET", "/api")
            statuses.append(status)
            if "retry-after" in headers:
                retry_after = headers["retry-after"]

        # First 3 requests should pass (200), subsequent should be 429
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3], 429)
        self.assertIsNotNone(retry_after)
        self.assertGreaterEqual(int(retry_after), 1)

    def test_rate_limit_replenish(self):
        # Wait for token bucket to replenish (1.2s at 2r/s adds >2 tokens)
        time.sleep(1.2)
        status, _, body = self.client.request("GET", "/api")
        self.assertEqual(status, 200)

    def test_strict_limit_503(self):
        # strict_zone: rate=1r/s, burst=0 -> only 1 request immediately
        status1, _, _ = self.client.request("GET", "/strict")
        self.assertEqual(status1, 200)
        status2, headers, _ = self.client.request("GET", "/strict")
        self.assertEqual(status2, 503)
        self.assertIn("retry-after", headers)

    def test_concurrency_limit(self):
        # /conn allows max 1 concurrent connection
        # Launch slow request in background thread
        results = []

        def worker():
            client = RawHttpClient(self.port)
            status, _, _ = client.request("GET", "/conn/slow")
            results.append(status)

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.08)  # ensure slow request is active

        # Concurrently send second request
        status2, _, _ = self.client.request("GET", "/conn")
        t.join()

        # One should be 200 (slow worker) and second should be 429
        self.assertEqual(results[0], 200)
        self.assertEqual(status2, 429)

        # After both finish, new request should succeed
        status3, _, _ = self.client.request("GET", "/conn")
        self.assertEqual(status3, 200)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("-") and not a.startswith("./")])
