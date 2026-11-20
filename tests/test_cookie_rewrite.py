#!/usr/bin/env python3
"""Integration tests for proxy_cookie_domain and proxy_cookie_path in Apex.

Covers:
- proxy_cookie_domain exact match rewriting
- proxy_cookie_domain suffix (.domain) match rewriting
- proxy_cookie_path prefix rewriting
- proxy_cookie_domain off and proxy_cookie_path off overrides in child location
- Multiple Set-Cookie headers in the same response
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


class CookieBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"cookie-response"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/single":
            self.send_header("Set-Cookie", "session=s1; Domain=backend.internal; Path=/backend/api; HttpOnly; Secure")
        elif self.path == "/subdomain":
            self.send_header("Set-Cookie", "user=alice; Domain=api.backend.internal; Path=/backend; SameSite=Lax")
        elif self.path == "/multiple":
            self.send_header("Set-Cookie", "c1=v1; Domain=backend.internal; Path=/backend/app")
            self.send_header("Set-Cookie", "c2=v2; Domain=other.internal; Path=/other/test")
        elif self.path == "/disabled":
            self.send_header("Set-Cookie", "token=secret; Domain=backend.internal; Path=/backend/api")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), CookieBackendHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


class RawHttpClient:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, headers=None):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
        req += "\r\n"
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
        status_line = lines[0]
        status_code = int(status_line.split()[1])

        parsed_headers = {}
        cookie_headers = []
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                k_lower = k.lower()
                parsed_headers[k_lower] = v
                if k_lower == "set-cookie":
                    cookie_headers.append(v)

        return status_code, parsed_headers, cookie_headers, body


class TestCookieRewrite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend, cls.backend_port = start_backend()
        cls.apex_port = free_port()

        config = f"""
http {{
    worker_connections 128;
    keepalive_timeout 60s;

    upstream cookie_pool {{
        server 127.0.0.1:{cls.backend_port};
    }}

    server {{
        listen 127.0.0.1:{cls.apex_port};
        server_name localhost;

        proxy_cookie_domain backend.internal public.example.com;
        proxy_cookie_domain .backend.internal .public.example.com;
        proxy_cookie_path /backend /frontend;

        location /single {{
            proxy_pass http://cookie_pool;
        }}

        location /subdomain {{
            proxy_pass http://cookie_pool;
        }}

        location /multiple {{
            proxy_cookie_domain other.internal external.com;
            proxy_cookie_path /other /target;
            proxy_pass http://cookie_pool;
        }}

        location /disabled {{
            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_pass http://cookie_pool;
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

    def test_01_exact_domain_and_path_rewrite(self):
        status, _, cookies, body = self.client.request("GET", "/single")
        self.assertEqual(status, 200)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Original: Set-Cookie: session=s1; Domain=backend.internal; Path=/backend/api; HttpOnly; Secure
        self.assertIn("Domain=public.example.com", cookie)
        self.assertIn("Path=/frontend/api", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertNotIn("backend.internal", cookie)
        self.assertNotIn("/backend/api", cookie)

    def test_02_subdomain_suffix_rewrite(self):
        status, _, cookies, _ = self.client.request("GET", "/subdomain")
        self.assertEqual(status, 200)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Original: user=alice; Domain=api.backend.internal; Path=/backend; SameSite=Lax
        self.assertIn("Domain=api.public.example.com", cookie)
        self.assertIn("Path=/frontend", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_03_multiple_cookies_and_location_override(self):
        status, _, cookies, _ = self.client.request("GET", "/multiple")
        self.assertEqual(status, 200)
        self.assertEqual(len(cookies), 2)
        # Location overridden rules: other.internal -> external.com, /other -> /target
        cookie1 = cookies[0]
        cookie2 = cookies[1]
        self.assertIn("Domain=external.com", cookie2)
        self.assertIn("Path=/target/test", cookie2)

    def test_04_cookie_rewrite_off(self):
        status, _, cookies, _ = self.client.request("GET", "/disabled")
        self.assertEqual(status, 200)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # When off: original backend cookie untouched
        self.assertIn("Domain=backend.internal", cookie)
        self.assertIn("Path=/backend/api", cookie)


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
