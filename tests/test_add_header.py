#!/usr/bin/env python3
"""Integration tests for add_header directive in Apex.

Covers:
- add_header in http, server, and location blocks
- Inheritance rules (location add_header replaces server/http add_header)
- Status code filtering (default applies to 200/201/204/206/301/302/303/304/307/308; skipped on 404/500)
- 'always' modifier (applies to all response codes including 404/500/502)
- Variable interpolation ($host, $status, $request_time, etc.)
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


class TestAddHeader(unittest.TestCase):
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

                    if b"/err500" in req_bytes:
                        resp = (
                            b"HTTP/1.1 500 Internal Error\r\n"
                            b"Content-Length: 5\r\n"
                            b"Connection: close\r\n\r\n"
                            b"error"
                        )
                    else:
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
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

    def test_01_http_and_server_and_location_inheritance(self):
        self.start_mock_upstream()
        doc_root = os.path.join(self.temp_dir.name, "html")
        os.makedirs(doc_root, exist_ok=True)
        with open(os.path.join(doc_root, "index.html"), "w") as f:
            f.write("Hello Static")

        conf = f"""
http {{
    add_header X-Global "GlobalValue";

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        add_header X-Server "ServerLevel";

        location /inherit {{
            root {doc_root};
        }}

        location /override {{
            add_header X-Custom "LocationCustom";
            root {doc_root};
        }}

        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)

        # /inherit should inherit from server level (X-Server)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/inherit/index.html")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Server"), "ServerLevel")
        self.assertIsNone(resp.getheader("X-Custom"))
        resp.read()
        conn.close()

        # /override has location-level add_header: replaces server/http headers
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/override/index.html")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Custom"), "LocationCustom")
        self.assertIsNone(resp.getheader("X-Server"))
        resp.read()
        conn.close()

        # /proxy should inherit X-Server on upstream response
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Server"), "ServerLevel")
        resp.read()
        conn.close()

    def test_02_status_filtering_and_always(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};

        add_header X-Success-Only "SuccessVal";
        add_header X-Always-Header "AlwaysVal" always;

        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 200 OK: both headers should be present
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Success-Only"), "SuccessVal")
        self.assertEqual(resp.getheader("X-Always-Header"), "AlwaysVal")
        resp.read()
        conn.close()

        # 500 error from upstream: only 'always' header should be present
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy/err500")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 500)
        self.assertIsNone(resp.getheader("X-Success-Only"))
        self.assertEqual(resp.getheader("X-Always-Header"), "AlwaysVal")
        resp.read()
        conn.close()

        # 404 error from server (non-matching route): only 'always' header
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/notfound")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        self.assertIsNone(resp.getheader("X-Success-Only"))
        self.assertEqual(resp.getheader("X-Always-Header"), "AlwaysVal")
        resp.read()
        conn.close()

    def test_03_variable_interpolation(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_name myhost.test;

        add_header X-Host "$host" always;
        add_header X-Status "$status" always;
        add_header X-Combined "Host-$host-Code-$status" always;

        location /proxy {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/proxy", headers={"Host": "myhost.test"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Host"), "myhost.test")
        self.assertEqual(resp.getheader("X-Status"), "200")
        self.assertEqual(resp.getheader("X-Combined"), "Host-myhost.test-Code-200")
        resp.read()
        conn.close()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
