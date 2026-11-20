#!/usr/bin/env python3
"""Integration tests for outgoing HTTPS upstream proxying in Apex.

Covers:
- proxy_pass https://...
- proxy_ssl_server_name on / off
- proxy_ssl_name <sni_name>
- Dynamic HTTPS proxying (proxy_pass https://$target_origin;)
"""

import http.client
import os
import socket
import ssl
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


def make_certificate(workdir, name):
    certificate = os.path.join(workdir, f"{name}.pem")
    key = os.path.join(workdir, f"{name}-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", certificate,
         "-days", "2", "-nodes", "-subj", "/CN=secure.backend.local"],
        check=True, capture_output=True, timeout=30,
    )
    return certificate, key


class TestHttpsProxy(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.upstream_tls_port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.cert, self.key = make_certificate(self.temp_dir.name, "backend")
        self.proc = None
        self.upstream_sock = None
        self.upstream_thread = None
        self.running = False
        self.last_sni = None

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

        self.running = False
        if self.upstream_sock:
            try:
                self.upstream_sock.close()
            except Exception:
                pass
            if self.upstream_thread:
                self.upstream_thread.join(timeout=2.0)

        self.temp_dir.cleanup()

    def start_mock_tls_upstream(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)

        def sni_callback(sslsock, server_name, initial_context):
            self.last_sni = server_name

        ctx.sni_callback = sni_callback

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(("127.0.0.1", self.upstream_tls_port))
        raw_sock.listen(10)
        self.upstream_sock = raw_sock
        self.running = True

        def run_loop():
            while self.running:
                try:
                    self.upstream_sock.settimeout(0.5)
                    raw_client, _ = self.upstream_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    client = ctx.wrap_socket(raw_client, server_side=True)
                    req_data = b""
                    while b"\r\n\r\n" not in req_data:
                        chunk = client.recv(1024)
                        if not chunk:
                            break
                        req_data += chunk

                    body = b"SECURE_UPSTREAM_OK"
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                        b"Connection: close\r\n\r\n" + body
                    )
                    client.sendall(resp)
                    client.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                finally:
                    try:
                        client.close()
                    except Exception:
                        pass

        self.upstream_thread = threading.Thread(target=run_loop, daemon=True)
        self.upstream_thread.start()

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

    def test_01_https_proxy_pass_with_sni(self):
        self.start_mock_tls_upstream()

        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};

        location /secure {{
            proxy_pass https://127.0.0.1:{self.upstream_tls_port};
            proxy_ssl_server_name on;
            proxy_ssl_name secure.backend.local;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/secure")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.read().decode("utf-8"), "SECURE_UPSTREAM_OK")
        conn.close()

        self.assertEqual(self.last_sni, "secure.backend.local")

    def test_02_dynamic_https_proxy_pass(self):
        self.start_mock_tls_upstream()

        conf = f"""
http {{
    map $host $sub_origin {{
        default 127.0.0.1:{self.upstream_tls_port};
        secure.app.net 127.0.0.1:{self.upstream_tls_port};
    }}

    server {{
        listen 127.0.0.1:{self.port};

        location /dynamic {{
            proxy_pass https://$sub_origin;
            proxy_ssl_server_name on;
            proxy_ssl_name $host;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/dynamic", headers={"Host": "secure.app.net"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.read().decode("utf-8"), "SECURE_UPSTREAM_OK")
        conn.close()

        self.assertEqual(self.last_sni, "secure.app.net")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
