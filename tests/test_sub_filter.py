#!/usr/bin/env python3
"""Integration tests for sub_filter, sub_filter_once, and sub_filter_types in Apex.

Covers:
- sub_filter once on (default: single occurrence replaced)
- sub_filter once off (all occurrences replaced)
- sub_filter_types for non-HTML responses (e.g. application/json)
- Content-Length header updated to match substituted length
- Non-matching MIME types bypassed
- Multiple sequential sub_filter rules
"""

import http.server
import json
import os
import socket
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


class SubFilterBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path in ("/html", "/single", "/all"):
            body = b"<html><body>Hello http://backend.internal and http://backend.internal/api</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/json":
            data = {"url": "http://backend.internal/v1", "backup": "http://backend.internal/v2"}
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/plain":
            body = b"Raw text with backend.internal"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/multi":
            body = b"foo and bar"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), SubFilterBackendHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


class RawHttpClient:
    def __init__(self, port):
        self.port = port

    def request(self, method, path):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))

        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()

        parts = raw.split(b"\r\n\r\n", 1)
        header_text = parts[0].decode("utf-8", errors="replace")
        body = parts[1] if len(parts) > 1 else b""

        lines = header_text.split("\r\n")
        status_code = int(lines[0].split()[1])

        parsed_headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                parsed_headers[k.lower()] = v

        return status_code, parsed_headers, body


class TestSubFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend, cls.backend_port = start_backend()
        cls.apex_port = free_port()

        config = f"""
http {{
    worker_connections 128;
    keepalive_timeout 60s;

    upstream sub_pool {{
        server 127.0.0.1:{cls.backend_port};
    }}

    server {{
        listen 127.0.0.1:{cls.apex_port};
        server_name localhost;

        location /single {{
            sub_filter 'http://backend.internal' 'https://public.cdn.com';
            sub_filter_once on;
            proxy_pass http://sub_pool;
        }}

        location /all {{
            sub_filter 'http://backend.internal' 'https://public.cdn.com';
            sub_filter_once off;
            proxy_pass http://sub_pool;
        }}

        location /json {{
            sub_filter 'http://backend.internal' 'https://public.cdn.com';
            sub_filter_once off;
            sub_filter_types application/json;
            proxy_pass http://sub_pool;
        }}

        location /plain {{
            # Default types is text/html only, so text/plain should not be modified
            sub_filter 'backend.internal' 'public.cdn.com';
            proxy_pass http://sub_pool;
        }}

        location /multi {{
            sub_filter 'foo' '111';
            sub_filter 'bar' '222';
            sub_filter_once off;
            proxy_pass http://sub_pool;
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(config)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", cls.apex_port), timeout=0.2)
                s.close()
                started = True
                break
            except (socket.error, ConnectionRefusedError):
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
        if os.path.exists(cls.conf_file.name):
            os.unlink(cls.conf_file.name)
        cls.backend.shutdown()

    def setUp(self):
        self.client = RawHttpClient(self.apex_port)

    def test_01_sub_filter_once_on(self):
        status, headers, body = self.client.request("GET", "/single")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        # First replaced, second remains
        self.assertIn("Hello https://public.cdn.com and http://backend.internal/api", text)
        cl = int(headers.get("content-length", 0))
        self.assertEqual(cl, len(body))

    def test_02_sub_filter_once_off(self):
        status, headers, body = self.client.request("GET", "/all")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        # Both replaced
        self.assertIn("Hello https://public.cdn.com and https://public.cdn.com/api", text)
        self.assertNotIn("http://backend.internal", text)
        cl = int(headers.get("content-length", 0))
        self.assertEqual(cl, len(body))

    def test_03_sub_filter_types_json(self):
        status, headers, body = self.client.request("GET", "/json")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["url"], "https://public.cdn.com/v1")
        self.assertEqual(data["backup"], "https://public.cdn.com/v2")
        cl = int(headers.get("content-length", 0))
        self.assertEqual(cl, len(body))

    def test_04_non_matching_mime_type_untouched(self):
        status, _, body = self.client.request("GET", "/plain")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"Raw text with backend.internal")

    def test_05_multiple_sub_filters(self):
        status, _, body = self.client.request("GET", "/multi")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"111 and 222")


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
