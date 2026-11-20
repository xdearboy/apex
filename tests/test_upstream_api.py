#!/usr/bin/env python3
"""Integration tests for Runtime Upstream Management API in Apex.

Covers:
- GET /api/ discovery endpoint
- GET /api/http/upstreams and GET /api/http/upstreams/{group}
- POST /api/http/upstreams/{group}/servers to dynamically add backends
- PATCH /api/http/upstreams/{group}/servers/{addr} to change weight and mark down
- DELETE /api/http/upstreams/{group}/servers/{addr} to remove backends
- Verification that traffic routing reflects runtime additions and down states
- Write-disabled location (api write=off) rejecting modifications with 403
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


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"backend-{self.server.server_address[1]}".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestUpstreamAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port_be1 = free_port()
        cls.port_be2 = free_port()
        cls.apex_port = free_port()

        cls.httpd1 = http.server.HTTPServer(("127.0.0.1", cls.port_be1), BackendHandler)
        cls.thread1 = threading.Thread(target=cls.httpd1.serve_forever, daemon=True)
        cls.thread1.start()

        cls.httpd2 = http.server.HTTPServer(("127.0.0.1", cls.port_be2), BackendHandler)
        cls.thread2 = threading.Thread(target=cls.httpd2.serve_forever, daemon=True)
        cls.thread2.start()

        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(f"""
http {{
    worker_connections 256;

    upstream app_pool {{
        server 127.0.0.1:{cls.port_be1} weight=1;
    }}

    server {{
        listen {cls.apex_port};

        location /api/ {{
            api write=on;
        }}

        location /api/ro/ {{
            api write=off;
        }}

        location /app/ {{
            proxy_pass http://app_pool;
        }}
    }}
}}
""")
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.apex_port), timeout=0.2):
                    started = True
                    break
            except OSError:
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
        cls.httpd1.shutdown()
        cls.httpd2.shutdown()
        os.unlink(cls.conf_file.name)

    def _request(self, method, path, body=None):
        with socket.create_connection(("127.0.0.1", self.apex_port), timeout=3.0) as sock:
            content = ""
            if body is not None:
                if isinstance(body, dict):
                    content = json.dumps(body)
                else:
                    content = str(body)
            body_bytes = content.encode("utf-8")

            req = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            if body is not None:
                req += "Content-Type: application/json\r\n"
                req += f"Content-Length: {len(body_bytes)}\r\n"
            req += "\r\n"

            sock.sendall(req.encode("utf-8") + body_bytes)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            header_part, _, body_part = resp.partition(b"\r\n\r\n")
            lines = header_part.decode("utf-8", errors="replace").split("\r\n")
            status_code = int(lines[0].split()[1])
            parsed_json = None
            if body_part:
                try:
                    parsed_json = json.loads(body_part.decode("utf-8"))
                except json.JSONDecodeError:
                    parsed_json = body_part.decode("utf-8", errors="replace")
            return status_code, parsed_json

    def test_01_api_discovery(self):
        """GET /api/ discovery endpoint."""
        status, data = self._request("GET", "/api/")
        self.assertEqual(status, 200)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("version"), "1.0")
        self.assertIn("upstreams", data.get("http", {}))

    def test_02_get_upstreams(self):
        """GET /api/http/upstreams returns current pool with backend 1."""
        status, data = self._request("GET", "/api/http/upstreams")
        self.assertEqual(status, 200)
        self.assertIn("app_pool", data)
        servers = data["app_pool"]["servers"]
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["server"], f"127.0.0.1:{self.port_be1}")
        self.assertFalse(servers[0]["down"])

    def test_03_post_server_and_traffic_balancing(self):
        """POST /api/http/upstreams/app_pool/servers dynamically adds backend 2."""
        new_server = {"server": f"127.0.0.1:{self.port_be2}", "weight": 1, "down": False}
        status, resp = self._request("POST", "/api/http/upstreams/app_pool/servers", body=new_server)
        self.assertEqual(status, 201)

        # Verify backend 2 is present in GET
        status, data = self._request("GET", "/api/http/upstreams/app_pool")
        self.assertEqual(status, 200)
        servers = data["servers"]
        self.assertEqual(len(servers), 2)
        addrs = [s["server"] for s in servers]
        self.assertIn(f"127.0.0.1:{self.port_be2}", addrs)

        # Verify traffic reaches backend 2
        seen_be2 = False
        for _ in range(10):
            s_code, resp_text = self._request("GET", "/app/test")
            self.assertEqual(s_code, 200)
            if f"backend-{self.port_be2}" in str(resp_text):
                seen_be2 = True
                break
        self.assertTrue(seen_be2, "Backend 2 should receive traffic after dynamic addition")

    def test_04_patch_server_mark_down(self):
        """PATCH /api/http/upstreams/app_pool/servers/{addr} marks backend 2 down."""
        target = f"127.0.0.1:{self.port_be2}"
        status, resp = self._request("PATCH", f"/api/http/upstreams/app_pool/servers/{target}", body={"down": True})
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("down"))

        # Traffic should now exclusively go to backend 1
        for _ in range(6):
            s_code, resp_text = self._request("GET", "/app/test")
            self.assertEqual(s_code, 200)
            self.assertIn(f"backend-{self.port_be1}", str(resp_text))

    def test_05_delete_server(self):
        """DELETE /api/http/upstreams/app_pool/servers/{addr} removes backend 2."""
        target = f"127.0.0.1:{self.port_be2}"
        status, resp = self._request("DELETE", f"/api/http/upstreams/app_pool/servers/{target}")
        self.assertEqual(status, 200)

        # Pool should now have only 1 server
        status, data = self._request("GET", "/api/http/upstreams/app_pool")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["servers"]), 1)
        self.assertEqual(data["servers"][0]["server"], f"127.0.0.1:{self.port_be1}")

    def test_06_write_disabled_forbidden(self):
        """Modifications are rejected with 403 on read-only API location."""
        new_server = {"server": f"127.0.0.1:{self.port_be2}", "weight": 1}
        # In a read-only location (/api/ro/), POST returns 403
        status, resp = self._request("POST", "/api/ro/http/upstreams/app_pool/servers", body=new_server)
        self.assertEqual(status, 403)
        self.assertIn("disabled", resp.get("error", ""))

        # Also test PATCH with nonexistent server on write-enabled location
        status_nf, _ = self._request("PATCH", "/api/http/upstreams/app_pool/servers/127.0.0.1:9999", body={"down": True})
        self.assertEqual(status_nf, 404)


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
