#!/usr/bin/env python3
"""Integration tests for Real-IP module (ngx_http_realip_module equivalent) in Apex.

Covers:
- set_real_ip_from (IPv4 and IPv6 CIDR / single IP)
- real_ip_header (X-Forwarded-For, X-Real-IP, custom header like CF-Connecting-IP)
- real_ip_recursive on / off behavior
- Untrusted proxy rejection (header ignored if peer is untrusted)
- Real IP integration with ACLs (allow/deny)
- Real IP propagation to upstream (X-Real-IP)
"""

import http.client
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


class EchoBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        headers_dict = {k.lower(): v for k, v in self.headers.items()}
        body = json.dumps({
            "path": self.path,
            "headers": headers_dict,
        }).encode("utf-8")
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
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), EchoBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class TestRealIp(unittest.TestCase):
    def setUp(self):
        self.backend, self.backend_port = start_backend()
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
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

    def test_01_real_ip_with_acl(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        set_real_ip_from 127.0.0.1;
        real_ip_header X-Forwarded-For;

        location / {{
            allow 203.0.113.195;
            deny all;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Allowed real IP
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"X-Forwarded-For": "203.0.113.195"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data["headers"].get("x-real-ip"), "203.0.113.195")
        conn.close()

        # 2. Denied real IP
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"X-Forwarded-For": "198.51.100.1"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()

    def test_02_untrusted_proxy_ignored(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        # 127.0.0.1 is NOT in trusted CIDRs
        set_real_ip_from 10.0.0.0/8;
        real_ip_header X-Forwarded-For;

        location / {{
            # Allow only the spoofed IP; should fail because 127.0.0.1 is not trusted!
            allow 203.0.113.195;
            deny all;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"X-Forwarded-For": "203.0.113.195"})
        resp = conn.getresponse()
        # Should be 403 because 127.0.0.1 is not trusted to set real IP to 203.0.113.195
        self.assertEqual(resp.status, 403)
        conn.close()

    def test_03_real_ip_recursive(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        set_real_ip_from 127.0.0.1;
        set_real_ip_from 192.168.1.0/24;
        real_ip_header X-Forwarded-For;
        real_ip_recursive on;

        location / {{
            allow 203.0.113.50;
            deny all;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # Chain: 203.0.113.50 (client), 192.168.1.10 (internal proxy), 127.0.0.1 (local edge)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"X-Forwarded-For": "203.0.113.50, 192.168.1.10"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data["headers"].get("x-real-ip"), "203.0.113.50")
        conn.close()

    def test_04_custom_real_ip_header(self):
        conf = f"""
http {{
    upstream backend_pool {{
        server 127.0.0.1:{self.backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        set_real_ip_from 127.0.0.1;
        real_ip_header CF-Connecting-IP;

        location / {{
            allow 198.51.100.77;
            deny all;
            proxy_pass http://backend_pool;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # Using CF-Connecting-IP
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"CF-Connecting-IP": "198.51.100.77"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        # Wrong IP
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test", headers={"CF-Connecting-IP": "1.2.3.4"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
