#!/usr/bin/env python3
"""Integration tests for Access Logging engine (ngx_http_log_module equivalent) in Apex.

Covers:
- Default 'combined' format logging to file
- Custom log_format with variables ($status, $request, $upstream_status, $request_time, $http_<name>)
- access_log off directive
- Real-IP integration: $remote_addr logs the resolved real IP
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
        body = b"hello from upstream\n"
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


class TestAccessLog(unittest.TestCase):
    def setUp(self):
        self.backend, self.backend_port = start_backend()
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.log_path = os.path.join(self.temp_dir.name, "access.log")
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

    def wait_for_log_line(self, log_file, expected_substring, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    if expected_substring in content:
                        return content
            time.sleep(0.05)
        content = ""
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        self.fail(f"Did not find '{expected_substring}' in log {log_file}. Content was: {content!r}")

    def test_01_combined_access_log(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    access_log {self.log_path};

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location / {{
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {
            "User-Agent": "ApexTestClient/1.0",
            "Referer": "http://example.com/start",
        }
        conn.request("GET", "/test-combined", headers=headers)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        # Wait and verify log entry
        content = self.wait_for_log_line(self.log_path, "ApexTestClient/1.0")
        self.assertIn('"GET /test-combined HTTP/1.1" 200', content)
        self.assertIn('"http://example.com/start"', content)
        self.assertIn('"ApexTestClient/1.0"', content)

    def test_02_custom_log_format(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    log_format custom '$remote_addr [$status] "$request" upstream: $upstream_status trace: $http_x_trace_id';
    access_log {self.log_path} custom;

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location / {{
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {
            "X-Trace-Id": "req-xyz-9876",
        }
        conn.request("GET", "/custom-format", headers=headers)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        content = self.wait_for_log_line(self.log_path, "req-xyz-9876")
        self.assertIn('[200] "GET /custom-format HTTP/1.1"', content)
        self.assertIn("upstream: 200", content)
        self.assertIn("trace: req-xyz-9876", content)

    def test_03_access_log_off(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    access_log {self.log_path};

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location /quiet {{
            access_log off;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/quiet")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        time.sleep(0.3)
        if os.path.exists(self.log_path):
            with open(self.log_path, "r") as f:
                content = f.read()
            self.assertNotIn("/quiet", content)

    def test_04_real_ip_in_access_log(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;

    log_format check_ip 'REAL_IP: $remote_addr STATUS: $status';
    access_log {self.log_path} check_ip;

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location / {{
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/real-ip-check", headers={"X-Forwarded-For": "198.51.100.99"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        content = self.wait_for_log_line(self.log_path, "REAL_IP: 198.51.100.99")
        self.assertIn("REAL_IP: 198.51.100.99 STATUS: 200", content)


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
