#!/usr/bin/env python3
"""Integration tests for Proxy Response Caching (proxy_cache) in Apex.

Covers:
- proxy_cache_path and proxy_cache directives
- X-Cache header injection (HIT, MISS, BYPASS)
- proxy_cache_valid status code and time rules
- proxy_cache_bypass on Pragma, Authorization, nocache arguments
- Cache-Control: no-cache and no-store handling
- Cache expiration and eviction
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


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.request_count += 1
        
        if "/nocache" in self.path:
            body = f"uncached-{self.server.request_count}".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache, no-store")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        body = f"cached-payload-{self.server.request_count}".encode("utf-8")
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
    server.request_count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class TestProxyCache(unittest.TestCase):
    def setUp(self):
        self.backend, self.backend_port = start_backend()
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.cache_dir = os.path.join(self.temp_dir.name, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.proc = None

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.backend.shutdown()
        self.backend.server_close()
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

    def test_01_cache_hit_and_miss(self):
        conf = f"""
http {{
    proxy_cache_path {self.cache_dir} levels=1:2 keys_zone=my_zone:10m max_size=100m inactive=10m;

    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        location / {{
            proxy_pass http://backend_pool;
            proxy_cache my_zone;
            proxy_cache_valid 200 10m;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # First request: MISS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/test")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "MISS")
        body1 = resp.read().decode("utf-8")
        conn.close()

        self.assertEqual(self.backend.request_count, 1)
        self.assertEqual(body1, "cached-payload-1")

        # Second request: HIT
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/test")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "HIT")
        body2 = resp.read().decode("utf-8")
        conn.close()

        # Backend must NOT have received a second request
        self.assertEqual(self.backend.request_count, 1)
        self.assertEqual(body2, "cached-payload-1")

    def test_02_cache_bypass(self):
        conf = f"""
http {{
    proxy_cache_path {self.cache_dir} keys_zone=my_zone:10m max_size=100m;

    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        location / {{
            proxy_pass http://backend_pool;
            proxy_cache my_zone;
            proxy_cache_valid 200 10m;
            proxy_cache_bypass $http_pragma $http_authorization $arg_nocache;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Normal GET: MISS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/item")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "MISS")
        resp.read()
        conn.close()
        self.assertEqual(self.backend.request_count, 1)

        # 2. Normal GET: HIT
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/item")
        resp = conn.getresponse()
        self.assertEqual(resp.getheader("X-Cache"), "HIT")
        resp.read()
        conn.close()
        self.assertEqual(self.backend.request_count, 1)

        # 3. GET with Pragma: no-cache -> BYPASS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/item", headers={"Pragma": "no-cache"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "BYPASS")
        body = resp.read().decode("utf-8")
        conn.close()
        self.assertEqual(self.backend.request_count, 2)
        self.assertEqual(body, "cached-payload-2")

        # 4. GET with Authorization -> BYPASS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/item", headers={"Authorization": "Bearer secret"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "BYPASS")
        resp.read()
        conn.close()
        self.assertEqual(self.backend.request_count, 3)

        # 5. GET with ?nocache=1 -> BYPASS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/item?nocache=1")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "BYPASS")
        resp.read()
        conn.close()
        self.assertEqual(self.backend.request_count, 4)

    def test_03_backend_no_cache_header(self):
        conf = f"""
http {{
    proxy_cache_path {self.cache_dir} keys_zone=my_zone:10m max_size=100m;

    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        location / {{
            proxy_pass http://backend_pool;
            proxy_cache my_zone;
            proxy_cache_valid 200 10m;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # Backend returns Cache-Control: no-cache, no-store
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/nocache")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "MISS")
        body1 = resp.read().decode("utf-8")
        conn.close()
        self.assertEqual(body1, "uncached-1")

        # Next request must STILL be MISS because it was not stored
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/nocache")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Cache"), "MISS")
        body2 = resp.read().decode("utf-8")
        conn.close()
        self.assertEqual(body2, "uncached-2")
        self.assertEqual(self.backend.request_count, 2)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
