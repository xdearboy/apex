#!/usr/bin/env python3
"""Integration tests for upstream balancing policies and server flags in Apex.

Covers:
- least_conn policy
- ip_hash policy
- server backup flag (hot standby, only routed to when all primaries fail)
- server down flag (administratively disabled, never routed to)
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


class IdentHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        backend_name = getattr(self.server, "backend_name", "backend")
        hook = getattr(self.server, "on_request", None)
        if hook:
            hook()
        delay = getattr(self.server, "delay", 0)
        if delay > 0:
            time.sleep(delay)
        body = backend_name.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", backend_name)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_backend(name, delay=0):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), IdentHandler)
    port = server.server_address[1]
    server.backend_name = name
    server.delay = delay
    server.on_request = None
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

        return status_code, body.decode("utf-8", "replace")


class UpstreamPoliciesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b1_server, cls.b1_port = start_backend("backend-primary")
        cls.b2_server, cls.b2_port = start_backend("backend-down")
        cls.fail_primary_server, cls.fail_primary_port = start_backend("failover-primary")
        cls.backup_server, cls.backup_port = start_backend("backend-backup")
        cls.slow_server, cls.slow_port = start_backend("backend-slow", delay=2.5)
        cls.fast_server, cls.fast_port = start_backend("backend-fast", delay=0)

        cls.port = free_port()
        cls.workdir = tempfile.mkdtemp(prefix="apex_test_upstream_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    upstream primary_pool {{
        server 127.0.0.1:{cls.b1_port};
        server 127.0.0.1:{cls.b2_port} down;
    }}

    upstream failover_pool {{
        max_retries 2;
        connect_timeout 500ms;
        server 127.0.0.1:{cls.fail_primary_port} max_fails=1 fail_timeout=5s;
        server 127.0.0.1:{cls.backup_port} backup;
    }}

    upstream least_conn_pool {{
        least_conn;
        server 127.0.0.1:{cls.slow_port};
        server 127.0.0.1:{cls.fast_port};
    }}

    upstream ip_hash_pool {{
        ip_hash;
        server 127.0.0.1:{cls.b1_port};
        server 127.0.0.1:{cls.fast_port};
    }}

    server {{
        listen 127.0.0.1:{cls.port};
        server_name localhost;

        location /primary {{
            proxy_pass http://primary_pool;
        }}

        location /failover {{
            proxy_pass http://failover_pool;
        }}

        location /least_conn {{
            proxy_pass http://least_conn_pool;
        }}

        location /ip_hash {{
            proxy_pass http://ip_hash_pool;
        }}
    }}
}}
"""
        with open(cls.conf_path, "w") as f:
            f.write(config)

        cls.proc = subprocess.Popen(
            [APEX, "-c", cls.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    started = True
                    break
            except OSError:
                time.sleep(0.05)

        if not started:
            cls.proc.kill()
            out, err = cls.proc.communicate()
            raise RuntimeError(f"Apex failed to start: {err.decode('utf-8', 'replace')}")

        cls.client = RawHttpClient(cls.port)

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()

        cls.b1_server.shutdown()
        cls.b1_server.server_close()
        cls.b2_server.shutdown()
        cls.b2_server.server_close()
        cls.fail_primary_server.shutdown()
        cls.fail_primary_server.server_close()
        cls.backup_server.shutdown()
        cls.backup_server.server_close()
        cls.slow_server.shutdown()
        cls.slow_server.server_close()
        cls.fast_server.shutdown()
        cls.fast_server.server_close()

    def test_01_primary_and_down_directive(self):
        # Primary is alive, down server should receive 0
        responses = []
        for _ in range(10):
            status, body = self.client.request("GET", "/primary")
            self.assertEqual(status, 200)
            responses.append(body)

        self.assertTrue(all(r == "backend-primary" for r in responses))
        self.assertFalse(any(r == "backend-down" for r in responses))

    def test_02_backup_failover_when_primary_down(self):
        # First request to failover_pool hits failover-primary
        status, body = self.client.request("GET", "/failover")
        self.assertEqual(status, 200)
        self.assertEqual(body, "failover-primary")

        # Now shut down failover_primary_server completely
        self.fail_primary_server.shutdown()
        self.fail_primary_server.server_close()

        # Next request fails over to backup server
        status, body = self.client.request("GET", "/failover")
        self.assertEqual(status, 200)
        self.assertEqual(body, "backend-backup")

    def test_03_least_conn_routing(self):
        # In least_conn_pool, slow server takes 1.0s, fast takes 0ms
        slow_in_flight = threading.Event()
        self.slow_server.on_request = slow_in_flight.set

        def slow_worker():
            client = RawHttpClient(self.port)
            client.request("GET", "/least_conn")

        t = threading.Thread(target=slow_worker)
        t.start()

        # Wait until slow server confirms request has arrived and is sleeping inside do_GET
        self.assertTrue(slow_in_flight.wait(timeout=5.0))

        # While slow server is busy, all subsequent requests must prefer fast server (0 active conns < 1)
        fast_client = RawHttpClient(self.port)
        fast_hits = 0
        for _ in range(5):
            status, body = fast_client.request("GET", "/least_conn")
            self.assertEqual(status, 200)
            if body == "backend-fast":
                fast_hits += 1

        t.join()
        self.slow_server.on_request = None
        self.assertEqual(fast_hits, 5)

    def test_04_ip_hash_consistency(self):
        # Repeated requests from same client IP must consistently reach the same backend
        first_backend = None
        for i in range(10):
            status, body = self.client.request("GET", "/ip_hash")
            self.assertEqual(status, 200)
            if first_backend is None:
                first_backend = body
            else:
                self.assertEqual(body, first_backend, f"ip_hash inconsistency on iteration {i}")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("-") and not a.startswith("./")])
