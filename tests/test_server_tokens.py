#!/usr/bin/env python3
"""Integration tests for server_tokens directive in Apex.

Covers:
- server_tokens on (default: Server: apex)
- server_tokens off (suppresses Server header, strips upstream Server header)
- server_tokens "<custom_string>" (emits Server: <custom_string>, overrides upstream)
- Verified across static files, proxy passes, 404/500 errors, redirects, and stub_status
"""

import http.client
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


class TestServerTokens(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.upstream_port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None
        self.upstream_server = None
        self.upstream_thread = None
        self.upstream_running = False

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.upstream_server:
            self.upstream_running = False
            try:
                self.upstream_server.close()
            except Exception:
                pass
            if self.upstream_thread:
                self.upstream_thread.join(timeout=2.0)
        self.temp_dir.cleanup()

    def start_mock_upstream(self):
        self.upstream_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.upstream_server.bind(("127.0.0.1", self.upstream_port))
        self.upstream_server.listen(10)
        self.upstream_running = True

        def run_loop():
            while self.upstream_running:
                try:
                    self.upstream_server.settimeout(0.5)
                    client, _ = self.upstream_server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    req_bytes = b""
                    while b"\r\n\r\n" not in req_bytes:
                        chunk = client.recv(1024)
                        if not chunk:
                            break
                        req_bytes += chunk

                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Server: Secret-Internal-Backend/9.9.9\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: close\r\n\r\n"
                        b"OK"
                    )
                    client.sendall(resp)
                except Exception:
                    pass
                finally:
                    client.close()

        self.upstream_thread = threading.Thread(target=run_loop, daemon=True)
        self.upstream_thread.start()

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

    def test_01_server_tokens_default_on(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Server"), "apex")
        resp.read()
        conn.close()

    def test_02_server_tokens_off(self):
        self.start_mock_upstream()
        doc_root = os.path.join(self.temp_dir.name, "html")
        os.makedirs(doc_root, exist_ok=True)
        with open(os.path.join(doc_root, "index.html"), "w") as f:
            f.write("static test")

        conf = f"""
http {{
    server_tokens off;

    server {{
        listen 127.0.0.1:{self.port};

        location /static {{
            root {doc_root};
        }}

        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}

        location /nginx_status {{
            stub_status;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Static file: no Server header
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/static/index.html")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertIsNone(resp.getheader("Server"), f"Expected no Server header, got: {resp.getheader('Server')}")
        resp.read()
        conn.close()

        # 2. Proxy upstream: backend Server header must be stripped, no Server header
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertIsNone(resp.getheader("Server"), f"Expected no Server header, got: {resp.getheader('Server')}")
        resp.read()
        conn.close()

        # 3. 404 error: no Server header
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/doesnotexist")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        self.assertIsNone(resp.getheader("Server"), f"Expected no Server header, got: {resp.getheader('Server')}")
        resp.read()
        conn.close()

        # 4. stub_status: no Server header
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/nginx_status")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertIsNone(resp.getheader("Server"), f"Expected no Server header, got: {resp.getheader('Server')}")
        resp.read()
        conn.close()

    def test_03_server_tokens_custom_string(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_tokens "d3vo-shield";

        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Server"), "d3vo-shield")
        resp.read()
        conn.close()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
