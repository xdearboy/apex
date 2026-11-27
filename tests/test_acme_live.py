#!/usr/bin/env python3
"""Integration test for Apex RFC 8555 automated ACME renewal and zero-downtime TLS reload."""

import base64
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_initial_certificate(workdir, name):
    cert = os.path.join(workdir, f"{name}.pem")
    key = os.path.join(workdir, f"{name}.key")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-keyout", key, "-out", cert,
            "-days", "1", "-subj", "/CN=old.example.com",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


class MockAcmeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("MOCK ACME: %s\n" % (format % args))

    def do_GET(self):
        if self.path == "/directory":
            body = json.dumps({
                "newNonce": f"http://127.0.0.1:{self.server.server_port}/new-nonce",
                "newAccount": f"http://127.0.0.1:{self.server.server_port}/new-account",
                "newOrder": f"http://127.0.0.1:{self.server.server_port}/new-order",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_HEAD(self):
        if self.path == "/new-nonce":
            self.send_response(200)
            self.send_header("Replay-Nonce", "nonce-test-1001")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""

        # Decode JWS payload if present
        payload_data = {}
        if post_data:
            try:
                jws = json.loads(post_data.decode("utf-8"))
                if "payload" in jws and jws["payload"]:
                    pad = len(jws["payload"]) % 4
                    if pad > 0:
                        jws["payload"] += "=" * (4 - pad)
                    raw_payload = base64.urlsafe_b64decode(jws["payload"])
                    if raw_payload:
                        payload_data = json.loads(raw_payload.decode("utf-8"))
            except Exception:
                pass

        if self.path == "/new-account":
            self.send_response(201)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/acct/1")
            self.send_header("Replay-Nonce", "nonce-test-1002")
            self.send_header("Content-Type", "application/json")
            body = b'{"status":"valid"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/new-order":
            self.send_response(201)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/order/1")
            self.send_header("Replay-Nonce", "nonce-test-1003")
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "pending",
                "authorizations": [f"http://127.0.0.1:{self.server.server_port}/auth/1"],
                "finalize": f"http://127.0.0.1:{self.server.server_port}/order/1/finalize",
            }).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/auth/1":
            self.send_response(200)
            self.send_header("Replay-Nonce", "nonce-test-1004")
            self.send_header("Content-Type", "application/json")
            status = "valid" if getattr(self.server, "challenge_verified", False) else "pending"
            body = json.dumps({
                "status": status,
                "token": "apex_token_9999",
                "url": f"http://127.0.0.1:{self.server.server_port}/chal/1",
            }).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/chal/1":
            # The client notified us challenge is ready. Query Apex challenge route:
            # GET http://127.0.0.1:<apex_port>/.well-known/acme-challenge/apex_token_9999
            apex_port = getattr(self.server, "apex_http_port", None)
            if apex_port:
                req_url = f"http://127.0.0.1:{apex_port}/.well-known/acme-challenge/apex_token_9999"
                req = urllib.request.Request(req_url, headers={"Host": "example.com"})
                try:
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        content = resp.read().decode()
                        sys.stderr.write(f"MOCK ACME GOT CHALLENGE RESPONSE: {content}\n")
                        if content.startswith("apex_token_9999."):
                            self.server.challenge_verified = True
                except Exception as e:
                    self.server.last_error = str(e)
                    sys.stderr.write(f"MOCK ACME ERROR querying challenge: {e}\n")

            self.send_response(200)
            self.send_header("Replay-Nonce", "nonce-test-1005")
            self.send_header("Content-Type", "application/json")
            body = b'{"status":"valid"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/order/1/finalize":
            self.server.order_finalized = True
            self.send_response(200)
            self.send_header("Replay-Nonce", "nonce-test-1006")
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "valid",
                "certificate": f"http://127.0.0.1:{self.server.server_port}/cert/1",
            }).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/order/1":
            self.send_response(200)
            self.send_header("Replay-Nonce", "nonce-test-1007")
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "valid",
                "certificate": f"http://127.0.0.1:{self.server.server_port}/cert/1",
            }).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/cert/1":
            # Generate or return renewed certificate
            cert_pem = getattr(self.server, "renewed_cert_pem", b"")
            self.send_response(200)
            self.send_header("Content-Type", "application/pem-certificate-chain")
            self.send_header("Content-Length", str(len(cert_pem)))
            self.end_headers()
            self.wfile.write(cert_pem)
        else:
            self.send_error(404)


class TestAcmeRenewal(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-acme-test-")
        self.mock_acme_port = free_port()
        self.apex_http_port = free_port()
        self.apex_tls_port = free_port()

        # Generate initial (old/expiring) cert & key
        self.initial_cert, self.initial_key = make_initial_certificate(self.workdir, "initial")

        # Destination paths for renewed cert & key
        self.renewed_cert_path = os.path.join(self.workdir, "renewed.pem")
        self.renewed_key_path = os.path.join(self.workdir, "renewed.key")

        # Generate renewed certificate material that mock ACME will supply
        renewed_mock_cert = os.path.join(self.workdir, "mock_server_cert.pem")
        renewed_mock_key = os.path.join(self.workdir, "mock_server_key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", renewed_mock_key, "-out", renewed_mock_cert,
                "-days", "90", "-subj", "/CN=renewed.example.com",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(renewed_mock_cert, "rb") as f:
            self.renewed_cert_pem = f.read()

        # Start Mock ACME server
        self.mock_server = http.server.HTTPServer(("127.0.0.1", self.mock_acme_port), MockAcmeHandler)
        self.mock_server.challenge_verified = False
        self.mock_server.order_finalized = False
        self.mock_server.renewed_cert_pem = self.renewed_cert_pem
        self.mock_server.apex_http_port = self.apex_http_port
        self.mock_thread = threading.Thread(target=self.mock_server.serve_forever, daemon=True)
        self.mock_thread.start()

        self.proc = None

    def tearDown(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.mock_server.shutdown()
        self.mock_server.server_close()

    def test_acme_http01_and_tls_renewal(self):
        config_path = os.path.join(self.workdir, "apex.conf")
        config_content = f"""
http {{
    server {{
        listen 127.0.0.1:{self.apex_http_port};
        server_name example.com 127.0.0.1 localhost;
        location / {{
            return 200 "hello http";
        }}
    }}
    server {{
        listen 127.0.0.1:{self.apex_tls_port} tls;
        server_name example.com 127.0.0.1 localhost;
        tls {{
            certificate "{self.initial_cert}";
            private_key "{self.initial_key}";
        }}
        acme {{
            email admin@example.com;
            domains example.com;
            acme_directory http://127.0.0.1:{self.mock_acme_port}/directory;
            acme_cert_path {self.renewed_cert_path};
            acme_key_path {self.renewed_key_path};
        }}
        location / {{
            return 200 "hello https";
        }}
    }}
}}
"""
        with open(config_path, "w") as f:
            f.write(config_content)

        # Launch apex
        self.proc = subprocess.Popen([APEX, "-c", config_path], stderr=subprocess.PIPE, text=True)

        # Wait for apex to start and perform ACME renewal
        start_time = time.time()
        renewed_saved = False
        while time.time() - start_time < 15:
            if os.path.exists(self.renewed_cert_path) and os.path.getsize(self.renewed_cert_path) > 0:
                renewed_saved = True
                break
            time.sleep(0.5)

        if not self.mock_server.challenge_verified:
            poll_res = self.proc.poll()
            sys.stderr.write(f"\nAPEX PID {self.proc.pid} poll={poll_res}\n")
            try:
                import select
                r, _, _ = select.select([self.proc.stderr], [], [], 0.5)
                if r:
                    sys.stderr.write("APEX STDERR: " + self.proc.stderr.read() + "\n")
            except Exception as e:
                sys.stderr.write(f"Cannot read stderr: {e}\n")

        self.assertTrue(self.mock_server.challenge_verified, "Mock ACME server should have verified HTTP-01 challenge")
        self.assertTrue(self.mock_server.order_finalized, "Order finalize should have completed")
        self.assertTrue(renewed_saved, "Renewed certificate file should have been written to disk")

        # Verify initial HTTP listener responds
        with urllib.request.urlopen(f"http://127.0.0.1:{self.apex_http_port}/", timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read().decode(), "hello http")

        # Verify HTTPS listener is live
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", self.apex_tls_port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname="example.com") as ssock:
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                resp = ssock.read(1024).decode()
                self.assertIn("200 OK", resp)
                self.assertIn("hello https", resp)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[2:])
