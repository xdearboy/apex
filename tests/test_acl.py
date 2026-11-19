#!/usr/bin/env python3
"""Integration tests for CIDR IP Access Control (allow / deny) in Apex.

Covers:
- Server-level allow / deny rules
- Location-level allow / deny rules
- Single IPv4 matching (/32)
- IPv4 subnet CIDR matching (e.g. 127.0.0.0/8)
- 'all' keyword
- First-match-wins rule evaluation order
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
        body = b"allowed-backend-ok"
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

        return status_code, body


class AclTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_server, cls.backend_port = start_backend()
        cls.port = free_port()

        cls.workdir = tempfile.mkdtemp(prefix="apex_test_acl_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    server {{
        listen 127.0.0.1:{cls.port};
        server_name server-denied.local;
        deny 127.0.0.1;
        allow all;

        location / {{
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}
    }}

    server {{
        listen 127.0.0.1:{cls.port};
        server_name loc-acl.local;

        location /whitelist-only {{
            allow 127.0.0.1;
            deny all;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}

        location /subnet-deny {{
            deny 127.0.0.0/8;
            allow all;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}

        location /first-match-wins {{
            allow 127.0.0.1;
            deny 127.0.0.0/8;
            allow all;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}

        location /deny-all {{
            deny all;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}

        location /public {{
            allow all;
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
            raise RuntimeError("Apex did not start in time for ACL test")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.backend_server.shutdown()

    def test_01_server_level_deny_exact_ip(self):
        client = RawHttpClient(self.port)
        status, _ = client.request("GET", "/", host="server-denied.local")
        self.assertEqual(status, 403)

    def test_02_location_whitelist_allows_exact_ip(self):
        client = RawHttpClient(self.port)
        status, body = client.request("GET", "/whitelist-only", host="loc-acl.local")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"allowed-backend-ok")

    def test_03_location_subnet_cidr_denies(self):
        client = RawHttpClient(self.port)
        status, _ = client.request("GET", "/subnet-deny", host="loc-acl.local")
        self.assertEqual(status, 403)

    def test_04_first_match_wins_precedence(self):
        # 127.0.0.1 is matched by allow 127.0.0.1 before deny 127.0.0.0/8
        client = RawHttpClient(self.port)
        status, body = client.request("GET", "/first-match-wins", host="loc-acl.local")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"allowed-backend-ok")

    def test_05_location_deny_all(self):
        client = RawHttpClient(self.port)
        status, _ = client.request("GET", "/deny-all", host="loc-acl.local")
        self.assertEqual(status, 403)

    def test_06_location_allow_all(self):
        client = RawHttpClient(self.port)
        status, body = client.request("GET", "/public", host="loc-acl.local")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"allowed-backend-ok")


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
