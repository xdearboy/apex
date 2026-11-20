#!/usr/bin/env python3
"""Integration tests for dynamic map directive and variable proxy_pass in Apex.

Covers:
- map $source $target { ... } directive in http block
- Exact match
- Wildcard prefix (*.domain.com, .domain.com)
- Wildcard suffix (domain.*)
- Default fallback
- Nested 'include map_file.conf;'
- Dynamic proxy_pass: proxy_pass http://$target_var;
- Dynamic variable expansion in add_header
"""

import http.client
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


class TestMap(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.upstream1_port = free_port()
        self.upstream2_port = free_port()
        self.default_upstream_port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None
        self.upstreams = []
        self.running = False

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

        self.running = False
        for s, th in self.upstreams:
            try:
                s.close()
            except Exception:
                pass
            th.join(timeout=1.0)

        self.temp_dir.cleanup()

    def start_mock_upstream(self, port, tag):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(10)

        def run_loop():
            while self.running:
                try:
                    sock.settimeout(0.5)
                    client, _ = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        chunk = client.recv(1024)
                        if not chunk:
                            break
                        buf += chunk

                    body = tag.encode("utf-8")
                    resp = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/plain\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("utf-8") + body
                    client.sendall(resp)
                except Exception:
                    pass
                finally:
                    client.close()

        th = threading.Thread(target=run_loop, daemon=True)
        th.start()
        self.upstreams.append((sock, th))

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

    def test_01_dynamic_map_and_proxy_pass(self):
        self.running = True
        self.start_mock_upstream(self.upstream1_port, "BACKEND_ONE")
        self.start_mock_upstream(self.upstream2_port, "BACKEND_TWO")
        self.start_mock_upstream(self.default_upstream_port, "BACKEND_DEFAULT")

        # Map include file
        include_path = os.path.join(self.temp_dir.name, "included_routes.map")
        with open(include_path, "w") as f:
            f.write(f"""
inc.example.org 127.0.0.1:{self.upstream1_port};
*.wildcard.org 127.0.0.1:{self.upstream2_port};
""")

        conf = f"""
http {{
    map $host $sub_origin {{
        default 127.0.0.1:{self.default_upstream_port};
        app1.local 127.0.0.1:{self.upstream1_port};
        app2.local 127.0.0.1:{self.upstream2_port};
        prefix.* 127.0.0.1:{self.upstream2_port};
        include {include_path};
    }}

    server {{
        listen 127.0.0.1:{self.port};

        add_header X-Mapped-Upstream "$sub_origin" always;

        location / {{
            proxy_pass http://$sub_origin;
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Exact match app1.local -> upstream 1
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "app1.local"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.upstream1_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_ONE")
        conn.close()

        # 2. Exact match app2.local -> upstream 2
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "app2.local"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.upstream2_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_TWO")
        conn.close()

        # 3. Suffix wildcard prefix.* -> prefix.corp.com
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "prefix.corp.com"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.upstream2_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_TWO")
        conn.close()

        # 4. Included exact match inc.example.org
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "inc.example.org"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.upstream1_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_ONE")
        conn.close()

        # 5. Included wildcard *.wildcard.org
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "sub.wildcard.org"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.upstream2_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_TWO")
        conn.close()

        # 6. Default fallback
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/", headers={"Host": "unknown-host.net"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Mapped-Upstream"), f"127.0.0.1:{self.default_upstream_port}")
        self.assertEqual(resp.read().decode("utf-8"), "BACKEND_DEFAULT")
        conn.close()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
