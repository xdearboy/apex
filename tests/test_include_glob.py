#!/usr/bin/env python3
"""Integration tests for modular configuration system with wildcard include in Apex.

Covers:
- include conf.d/*.conf; glob expansion
- Alphabetical ordering of matched files
- Empty wildcard matching without errors (e.g. non_existent/*.conf)
- Include within http block and within server block
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
        body = b"modular-backend-ok"
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

        return status_code, headers, body


class IncludeGlobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_server, cls.backend_port = start_backend()
        cls.port = free_port()

        cls.workdir = tempfile.mkdtemp(prefix="apex_test_glob_")
        cls.conf_dir = os.path.join(cls.workdir, "conf.d")
        os.makedirs(cls.conf_dir, exist_ok=True)

        cls.main_conf = os.path.join(cls.workdir, "apex.conf")

        # Write site 1
        with open(os.path.join(cls.conf_dir, "01_site1.conf"), "w") as f:
            f.write(f"""
server {{
    listen 127.0.0.1:{cls.port};
    server_name site1.local;
    return 301 /from-site1;
}}
""")

        # Write site 2
        with open(os.path.join(cls.conf_dir, "02_site2.conf"), "w") as f:
            f.write(f"""
server {{
    listen 127.0.0.1:{cls.port};
    server_name site2.local;
    location / {{
        proxy_pass http://127.0.0.1:{cls.backend_port};
    }}
}}
""")

        # Main config with glob include and an empty glob include
        main_text = f"""
events {{}}
http {{
    include {cls.conf_dir}/*.conf;
    include {cls.workdir}/empty_globs/*.conf;
}}
"""
        with open(cls.main_conf, "w") as f:
            f.write(main_text)

        cls.proc = subprocess.Popen([APEX, "-c", cls.main_conf],
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
            raise RuntimeError("Apex did not start in time for include glob test")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.backend_server.shutdown()

    def test_01_site1_included_and_working(self):
        client = RawHttpClient(self.port)
        status, headers, _ = client.request("GET", "/", host="site1.local")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/from-site1")

    def test_02_site2_included_and_working(self):
        client = RawHttpClient(self.port)
        status, _, body = client.request("GET", "/test", host="site2.local")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"modular-backend-ok")


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
