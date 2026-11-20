#!/usr/bin/env python3
"""Integration tests for high-availability failover & upstream error interception in Apex.

Covers:
- proxy_next_upstream with http_502 / http_500 transparent failover
- proxy_next_upstream error / connection refused transparent failover
- proxy_next_upstream_tries limit enforcement
- proxy_next_upstream off directive
- Idempotent (GET) vs Non-idempotent (POST) failover behavior
- proxy_next_upstream non_idempotent flag
- proxy_intercept_errors on serving custom error_page
- proxy_intercept_errors off preserving upstream response
- Location-level error_page override
"""

import http.client
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FailoverHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.handle_req()

    def do_POST(self):
        self.handle_req()

    def handle_req(self):
        status = getattr(self.server, "status", 200)
        body = getattr(self.server, "body", b"OK")
        backend_name = getattr(self.server, "backend_name", "backend")
        self.server.request_count = getattr(self.server, "request_count", 0) + 1

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", backend_name)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_mock_backend(name, status=200, body=b"OK"):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FailoverHandler)
    server.backend_name = name
    server.status = status
    server.body = body
    server.request_count = 0
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class TestFailover(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None
        self.servers_to_close = []

    def tearDown(self):
        for s in self.servers_to_close:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
        self.temp_dir.cleanup()

    def start_apex(self, conf_content):
        with open(self.conf_path, "w", encoding="utf-8") as f:
            f.write(conf_content)
        self.proc = subprocess.Popen(
            [APEX, "-c", self.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                if self.proc.poll() is not None:
                    out, err = self.proc.communicate()
                    raise RuntimeError(f"Apex exited early ({self.proc.returncode}):\n{out}\n{err}")
                time.sleep(0.05)
        raise TimeoutError("Apex did not start in time")

    def request(self, method="GET", path="/", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            res = conn.getresponse()
            data = res.read()
            return res.status, res.headers, data
        finally:
            conn.close()

    def test_failover_http_502(self):
        """Backend 1 returns 502, Apex fails over to Backend 2 which returns 200."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Backend 1 Bad Gateway")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 Success")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout http_502;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Backend 2 Success")
        self.assertEqual(headers.get("X-Backend"), "b2")
        self.assertEqual(b1.request_count, 1)
        self.assertEqual(b2.request_count, 1)

    def test_failover_http_500(self):
        """Backend 1 returns 500, Apex fails over to Backend 2 which returns 200."""
        b1, p1 = start_mock_backend("b1", status=500, body=b"Backend 1 Internal Error")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 OK")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout http_500;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Backend 2 OK")
        self.assertEqual(headers.get("X-Backend"), "b2")

    def test_failover_connection_refused(self):
        """Backend 1 is down (closed port), Apex fails over to Backend 2."""
        closed_port = free_port()
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 Up")
        self.servers_to_close.append(b2)

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{closed_port};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Backend 2 Up")
        self.assertEqual(headers.get("X-Backend"), "b2")

    def test_next_upstream_tries_limit(self):
        """proxy_next_upstream_tries 1 ensures no second attempt is made."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Backend 1 Bad Gateway")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 Success")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout http_502;
                    proxy_next_upstream_tries 1;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 502)
        self.assertEqual(data, b"Backend 1 Bad Gateway")
        self.assertEqual(b1.request_count, 1)
        self.assertEqual(b2.request_count, 0)

    def test_next_upstream_off(self):
        """proxy_next_upstream off disables failover completely."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Backend 1 502")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 200")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream off;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 502)
        self.assertEqual(data, b"Backend 1 502")
        self.assertEqual(b1.request_count, 1)
        self.assertEqual(b2.request_count, 0)

    def test_non_idempotent_post_without_flag(self):
        """POST request without non_idempotent flag does not failover on 500."""
        b1, p1 = start_mock_backend("b1", status=500, body=b"Backend 1 POST Failed")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 POST Success")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout http_500;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("POST", "/", body=b"payload=123")
        self.assertEqual(status, 500)
        self.assertEqual(data, b"Backend 1 POST Failed")
        self.assertEqual(b1.request_count, 1)
        self.assertEqual(b2.request_count, 0)

    def test_non_idempotent_post_with_flag(self):
        """POST request with non_idempotent flag retries on Backend 2."""
        b1, p1 = start_mock_backend("b1", status=500, body=b"Backend 1 POST Failed")
        b2, p2 = start_mock_backend("b2", status=200, body=b"Backend 2 POST Success")
        self.servers_to_close.extend([b1, b2])

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
                server 127.0.0.1:{p2};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                location / {{
                    proxy_pass http://cluster;
                    proxy_next_upstream error timeout http_500 non_idempotent;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("POST", "/", body=b"payload=123")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Backend 2 POST Success")
        self.assertEqual(b1.request_count, 1)
        self.assertEqual(b2.request_count, 1)

    def test_proxy_intercept_errors_on(self):
        """proxy_intercept_errors on intercepts 502 and renders custom error_page."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Raw Backend 502")
        self.servers_to_close.append(b1)

        err_file = os.path.join(self.temp_dir.name, "custom_502.html")
        with open(err_file, "w", encoding="utf-8") as f:
            f.write("<html><body><h1>Branded Custom 502 Error Page</h1></body></html>")

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                error_page 502 {err_file};

                location / {{
                    proxy_pass http://cluster;
                    proxy_intercept_errors on;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 502)
        self.assertIn(b"Branded Custom 502 Error Page", data)

    def test_proxy_intercept_errors_off(self):
        """proxy_intercept_errors off delivers raw backend 502 without intercepting."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Raw Backend 502 Body")
        self.servers_to_close.append(b1)

        err_file = os.path.join(self.temp_dir.name, "custom_502.html")
        with open(err_file, "w", encoding="utf-8") as f:
            f.write("<html><body><h1>Branded Custom 502 Error Page</h1></body></html>")

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                error_page 502 {err_file};

                location / {{
                    proxy_pass http://cluster;
                    proxy_intercept_errors off;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 502)
        self.assertEqual(data, b"Raw Backend 502 Body")

    def test_location_error_page_override(self):
        """Location-level error_page overrides server-level error_page."""
        b1, p1 = start_mock_backend("b1", status=502, body=b"Raw Backend 502")
        self.servers_to_close.append(b1)

        server_err = os.path.join(self.temp_dir.name, "server_502.html")
        with open(server_err, "w", encoding="utf-8") as f:
            f.write("Server Level Error Page")

        loc_err = os.path.join(self.temp_dir.name, "location_502.html")
        with open(loc_err, "w", encoding="utf-8") as f:
            f.write("Location Level Error Page")

        conf = f"""
        http {{
            upstream cluster {{
                server 127.0.0.1:{p1};
            }}

            server {{
                listen 127.0.0.1:{self.port};
                error_page 502 {server_err};

                location / {{
                    proxy_pass http://cluster;
                    error_page 502 {loc_err};
                    proxy_intercept_errors on;
                }}
            }}
        }}
        """
        self.start_apex(conf)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 502)
        self.assertIn(b"Location Level Error Page", data)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
