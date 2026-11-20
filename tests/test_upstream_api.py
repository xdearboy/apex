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
- API Key / Secret Token verification (Authorization: Bearer, X-API-Key, ?api_key=, ?secret=)
- HTTP Basic Auth verification (Authorization: Basic <base64>, 401 with WWW-Authenticate)
- Location ACL access control (403 Forbidden on denied IP)
- Thread safety and concurrency during active traffic and API mutations
"""

import base64
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

        cls.htpasswd_file = tempfile.NamedTemporaryFile("w", suffix=".htpasswd", delete=False)
        cls.htpasswd_file.write("admin:secretpass123\noperator:testpass456\n")
        cls.htpasswd_file.flush()
        cls.htpasswd_file.close()

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

        location /api/secure/ {{
            api write=on secret="secret-apex-token-123";
        }}

        location /api/basic/ {{
            api write=on;
            auth_basic "Apex API Realm";
            auth_basic_user_file "{cls.htpasswd_file.name}";
        }}

        location /api/blocked/ {{
            api write=on;
            deny 127.0.0.1;
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
        os.unlink(cls.htpasswd_file.name)

    def _request(self, method, path, body=None, headers=None):
        status, parsed, _ = self._request_full(method, path, body=body, headers=headers)
        return status, parsed

    def _request_full(self, method, path, body=None, headers=None):
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
            if headers:
                for k, v in headers.items():
                    req += f"{k}: {v}\r\n"
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
            resp_headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    resp_headers[k.lower()] = v
            parsed_json = None
            if body_part:
                try:
                    parsed_json = json.loads(body_part.decode("utf-8"))
                except json.JSONDecodeError:
                    parsed_json = body_part.decode("utf-8", errors="replace")
            return status_code, parsed_json, resp_headers

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
        status, resp = self._request("POST", "/api/ro/http/upstreams/app_pool/servers", body=new_server)
        self.assertEqual(status, 403)
        self.assertIn("disabled", resp.get("error", ""))

        status_nf, _ = self._request("PATCH", "/api/http/upstreams/app_pool/servers/127.0.0.1:9999", body={"down": True})
        self.assertEqual(status_nf, 404)

    def test_07_api_secret_unauthorized(self):
        """Requests without secret token return 401 Unauthorized with Bearer challenge."""
        status, resp, headers = self._request_full("GET", "/api/secure/http/upstreams")
        self.assertEqual(status, 401)
        self.assertIn("bearer realm=\"apex-api\"", headers.get("www-authenticate", "").lower())
        self.assertIn("unauthorized", resp.get("error", "").lower())

    def test_08_api_secret_bearer_token(self):
        """Requests with Authorization: Bearer <secret> succeed."""
        status, data = self._request("GET", "/api/secure/http/upstreams",
                                     headers={"Authorization": "Bearer secret-apex-token-123"})
        self.assertEqual(status, 200)
        self.assertIn("app_pool", data)

    def test_09_api_secret_x_api_key_header(self):
        """Requests with X-API-Key: <secret> succeed."""
        status, data = self._request("GET", "/api/secure/http/upstreams",
                                     headers={"X-API-Key": "secret-apex-token-123"})
        self.assertEqual(status, 200)
        self.assertIn("app_pool", data)

    def test_10_api_secret_query_params(self):
        """Requests with query params ?api_key=<secret> or ?secret=<secret> succeed."""
        status, data = self._request("GET", "/api/secure/http/upstreams?api_key=secret-apex-token-123")
        self.assertEqual(status, 200)
        self.assertIn("app_pool", data)

        status2, data2 = self._request("GET", "/api/secure/http/upstreams?secret=secret-apex-token-123")
        self.assertEqual(status2, 200)
        self.assertIn("app_pool", data2)

    def test_11_api_secret_invalid_rejected(self):
        """Requests with invalid secret are rejected with 401."""
        status, resp = self._request("GET", "/api/secure/http/upstreams",
                                     headers={"Authorization": "Bearer wrong-key"})
        self.assertEqual(status, 401)
        self.assertIn("unauthorized", resp.get("error", "").lower())

    def test_12_api_basic_auth_unauthorized(self):
        """Requests to basic auth location without credentials return 401 with Basic challenge."""
        status, _, headers = self._request_full("GET", "/api/basic/http/upstreams")
        self.assertEqual(status, 401)
        self.assertIn("basic realm=\"apex api realm\"", headers.get("www-authenticate", "").lower())

    def test_13_api_basic_auth_success(self):
        """Requests with valid htpasswd basic auth credentials succeed."""
        creds = base64.b64encode(b"admin:secretpass123").decode("ascii")
        status, data = self._request("GET", "/api/basic/http/upstreams",
                                     headers={"Authorization": f"Basic {creds}"})
        self.assertEqual(status, 200)
        self.assertIn("app_pool", data)

    def test_14_api_basic_auth_wrong_password(self):
        """Requests with invalid password return 401."""
        creds = base64.b64encode(b"admin:wrongpassword").decode("ascii")
        status, _ = self._request("GET", "/api/basic/http/upstreams",
                                  headers={"Authorization": f"Basic {creds}"})
        self.assertEqual(status, 401)

    def test_15_api_acl_blocked_ip(self):
        """Location ACL deny rules block unauthorized IP addresses with 403."""
        status, _ = self._request("GET", "/api/blocked/http/upstreams")
        self.assertEqual(status, 403)

    def test_16_concurrent_traffic_and_api_mutation(self):
        """Mutating upstreams concurrently with high traffic load does not cause data races or crashes."""
        stop_event = threading.Event()
        errors = []

        def worker():
            while not stop_event.is_set():
                try:
                    s_code, _ = self._request("GET", "/app/test")
                    if s_code != 200:
                        errors.append(f"Expected 200, got {s_code}")
                except Exception as e:
                    errors.append(str(e))
                time.sleep(0.005)

        workers = [threading.Thread(target=worker) for _ in range(4)]
        for w in workers:
            w.start()

        target = f"127.0.0.1:{self.port_be1}"
        for i in range(10):
            weight = (i % 5) + 1
            s, _ = self._request("PATCH", f"/api/http/upstreams/app_pool/servers/{target}",
                                 body={"weight": weight, "down": False})
            self.assertEqual(s, 200)
            time.sleep(0.01)

        stop_event.set()
        for w in workers:
            w.join(timeout=2.0)

        self.assertEqual(len(errors), 0, f"Concurrent workers experienced errors: {errors[:5]}")


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
