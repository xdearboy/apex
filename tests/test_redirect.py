#!/usr/bin/env python3
"""Integration tests for HTTP redirects (return directive) in Apex.

Covers:
- Server-level return 301 https://$host$request_uri;
- Location-level return 302 /new-destination;
- Status codes: 301, 302, 307, 308
- Query string preservation in $request_uri
- Coexistence with proxy locations in the same server block
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

    def request(self, method, path, host="127.0.0.1", extra_headers=None):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        if extra_headers:
            for k, v in extra_headers.items():
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
        headers_raw = parts[0].decode("utf-8", "replace")
        body = parts[1] if len(parts) > 1 else b""
        lines = headers_raw.split("\r\n")
        status_line = lines[0]
        status_code = int(status_line.split(" ")[1])

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status_code, headers, body


class RedirectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_server, cls.backend_port = start_backend()
        cls.port = free_port()

        cls.workdir = tempfile.mkdtemp(prefix="apex_test_redirect_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    server {{
        listen 127.0.0.1:{cls.port};
        server_name redirect.example.com;
        return 301 https://$host$request_uri;
    }}

    server {{
        listen 127.0.0.1:{cls.port};
        server_name app.example.com;

        location /temp {{
            return 302 /temporary-dest;
        }}

        location /preserve-method {{
            return 307 /temp-preserve;
        }}

        location /perm-preserve {{
            return 308 /perm-preserve-dest;
        }}

        location /expand {{
            return 301 https://$host/prefixed$request_uri;
        }}

        location /backend {{
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}
    }}
}}
"""
        with open(cls.conf_path, "w") as f:
            f.write(config)

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

        deadline = time.time() + START_TIMEOUT
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            cls.proc.kill()
            raise RuntimeError("Apex did not start in time for redirect test")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.backend_server.shutdown()

    def test_01_server_level_301_redirect(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("GET", "/login?ref=dashboard", host="redirect.example.com")
        self.assertEqual(status, 301)
        self.assertIn("location", headers)
        self.assertEqual(headers["location"], "https://redirect.example.com/login?ref=dashboard")

    def test_02_location_level_302_redirect(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("GET", "/temp", host="app.example.com")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("location"), "/temporary-dest")

    def test_03_location_level_307_temporary_redirect(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("POST", "/preserve-method", host="app.example.com")
        self.assertEqual(status, 307)
        self.assertEqual(headers.get("location"), "/temp-preserve")

    def test_04_location_level_308_permanent_redirect(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("POST", "/perm-preserve", host="app.example.com")
        self.assertEqual(status, 308)
        self.assertEqual(headers.get("location"), "/perm-preserve-dest")

    def test_05_location_variable_expansion(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("GET", "/expand?key=val", host="app.example.com")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "https://app.example.com/prefixed/expand?key=val")

    def test_06_non_redirect_location_still_proxies(self):
        client = RawHttpClient(self.port)
        status, _, body = client.request("GET", "/backend", host="app.example.com")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"backend-ok")


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
