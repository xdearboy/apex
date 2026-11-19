#!/usr/bin/env python3
"""Integration tests for Proxy Headers & Variable Expansion in Apex.

Covers:
- Authoritative X-Real-IP injection (overwriting client-spoofed header)
- X-Forwarded-For appending and chaining
- X-Forwarded-Proto and X-Forwarded-Host injection
- Dynamic Nginx variable expansion in proxy_set_header:
  $host, $remote_addr, $scheme, $request_uri
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

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HeaderEchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        dump = {k.lower(): v for k, v in self.headers.items()}
        dump["_path"] = self.path
        body = json.dumps(dump).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), HeaderEchoHandler)
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
        status_code = int(lines[0].split(" ")[1])

        data = json.loads(body.decode("utf-8")) if status_code == 200 else {}
        return status_code, data


class ProxyHeadersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_server, cls.backend_port = start_backend()
        cls.port = free_port()

        cls.workdir = tempfile.mkdtemp(prefix="apex_test_headers_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    server {{
        listen 127.0.0.1:{cls.port};
        server_name proxy-headers.local;

        location /standard {{
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}

        location /custom {{
            proxy_pass http://127.0.0.1:{cls.backend_port};
            proxy_set_header X-Custom-Host "$host";
            proxy_set_header X-Custom-Client "$remote_addr";
            proxy_set_header X-Custom-Scheme "$scheme";
            proxy_set_header X-Custom-URI "$request_uri";
            proxy_set_header X-Static-Tag "Apex-ReverseProxy-v1";
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
            raise RuntimeError("Apex did not start in time for proxy headers test")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.backend_server.shutdown()

    def test_01_standard_proxy_headers(self):
        client = RawHttpClient(self.port)
        status, headers = client.request("GET", "/standard", host="proxy-headers.local")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-real-ip"), "127.0.0.1")
        self.assertEqual(headers.get("x-forwarded-for"), "127.0.0.1")
        self.assertEqual(headers.get("x-forwarded-proto"), "http")
        self.assertEqual(headers.get("x-forwarded-host"), "proxy-headers.local")

    def test_02_spoofed_real_ip_is_overwritten(self):
        client = RawHttpClient(self.port)
        status, headers = client.request(
            "GET", "/standard", host="proxy-headers.local",
            extra_headers={"X-Real-IP": "10.0.0.1"}
        )
        self.assertEqual(status, 200)
        # Apex must overwrite spoofed X-Real-IP with actual peer IP
        self.assertEqual(headers.get("x-real-ip"), "127.0.0.1")

    def test_03_forwarded_for_chaining(self):
        client = RawHttpClient(self.port)
        status, headers = client.request(
            "GET", "/standard", host="proxy-headers.local",
            extra_headers={"X-Forwarded-For": "203.0.113.195"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-forwarded-for"), "203.0.113.195, 127.0.0.1")

    def test_04_custom_headers_variable_expansion(self):
        client = RawHttpClient(self.port)
        status, headers = client.request(
            "GET", "/custom?query=42&sort=desc", host="proxy-headers.local"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-custom-host"), "proxy-headers.local")
        self.assertEqual(headers.get("x-custom-client"), "127.0.0.1")
        self.assertEqual(headers.get("x-custom-scheme"), "http")
        self.assertEqual(headers.get("x-custom-uri"), "/custom?query=42&sort=desc")
        self.assertEqual(headers.get("x-static-tag"), "Apex-ReverseProxy-v1")


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
