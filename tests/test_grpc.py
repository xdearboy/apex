#!/usr/bin/env python3
"""Integration tests for gRPC end-to-end reverse proxying with HTTP/2 and trailers."""

import http.server
import os
import re
import shutil
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
STOP_TIMEOUT = 10.0
REQUEST_TIMEOUT = 10.0


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_certificate(workdir, name):
    cert = os.path.join(workdir, f"{name}.pem")
    key = os.path.join(workdir, f"{name}-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
         "-days", "2", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True, timeout=30,
    )
    return cert, key


class GrpcBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        req_body = self.rfile.read(length) if length > 0 else b""

        if self.path == "/test.TestService/TrailersOnly":
            # Immediate error response (Trailers-Only, no body)
            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("grpc-status", "16")
            self.send_header("grpc-message", "Unauthenticated")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path == "/test.TestService/UnaryCall":
            # Length-prefixed gRPC message response + trailers in chunked encoding
            msg_payload = b"Hello " + (req_body[5:] if len(req_body) > 5 else b"gRPC")
            # 1 byte compressed flag (0) + 4 bytes big-endian length
            grpc_message = b"\x00" + len(msg_payload).to_bytes(4, "big") + msg_payload

            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            # Send data chunk
            chunk_header = f"{len(grpc_message):x}\r\n".encode("ascii")
            self.wfile.write(chunk_header + grpc_message + b"\r\n")

            # Send chunked trailers
            self.wfile.write(b"0\r\n")
            self.wfile.write(b"grpc-status: 0\r\n")
            self.wfile.write(b"grpc-message: OK\r\n")
            self.wfile.write(b"x-custom-meta: apex-grpc-pass\r\n")
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return

        if self.path == "/test.TestService/ServerStreaming":
            # Server-streaming: client sends 1 request, server returns 5 sequential gRPC messages
            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            for i in range(1, 6):
                payload = f"StreamItem-{i}".encode("ascii")
                msg = b"\x00" + len(payload).to_bytes(4, "big") + payload
                chunk_header = f"{len(msg):x}\r\n".encode("ascii")
                self.wfile.write(chunk_header + msg + b"\r\n")

            self.wfile.write(b"0\r\n")
            self.wfile.write(b"grpc-status: 0\r\n")
            self.wfile.write(b"grpc-message: OK\r\n")
            self.wfile.write(b"x-stream-count: 5\r\n")
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return

        if self.path == "/test.TestService/ClientStreaming":
            # Client-streaming: client sends multiple gRPC messages in request body
            # Parse length-prefixed messages
            items = []
            idx = 0
            while idx + 5 <= len(req_body):
                msg_len = int.from_bytes(req_body[idx + 1:idx + 5], "big")
                if idx + 5 + msg_len <= len(req_body):
                    items.append(req_body[idx + 5:idx + 5 + msg_len])
                idx += 5 + msg_len

            summary_payload = f"Received {len(items)} items: {b','.join(items).decode('utf-8', 'replace')}".encode("ascii")
            grpc_message = b"\x00" + len(summary_payload).to_bytes(4, "big") + summary_payload

            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            chunk_header = f"{len(grpc_message):x}\r\n".encode("ascii")
            self.wfile.write(chunk_header + grpc_message + b"\r\n")

            self.wfile.write(b"0\r\n")
            self.wfile.write(b"grpc-status: 0\r\n")
            self.wfile.write(b"grpc-message: OK\r\n")
            self.wfile.write(f"x-items-received: {len(items)}\r\n".encode("ascii"))
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return

        if self.path == "/test.TestService/BidiStreaming":
            # Bidirectional streaming: client sends N pings, server replies with N pongs
            items = []
            idx = 0
            while idx + 5 <= len(req_body):
                msg_len = int.from_bytes(req_body[idx + 1:idx + 5], "big")
                if idx + 5 + msg_len <= len(req_body):
                    items.append(req_body[idx + 5:idx + 5 + msg_len])
                idx += 5 + msg_len

            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            for item in items:
                reply_payload = b"Pong-" + item
                msg = b"\x00" + len(reply_payload).to_bytes(4, "big") + reply_payload
                chunk_header = f"{len(msg):x}\r\n".encode("ascii")
                self.wfile.write(chunk_header + msg + b"\r\n")

            self.wfile.write(b"0\r\n")
            self.wfile.write(b"grpc-status: 0\r\n")
            self.wfile.write(b"grpc-message: OK\r\n")
            self.wfile.write(f"x-pongs-sent: {len(items)}\r\n".encode("ascii"))
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


class TestGrpcReverseProxy(unittest.TestCase):
    def setUp(self):
        probe = subprocess.run(["curl", "--version"], capture_output=True, text=True)
        if "nghttp2" not in probe.stdout:
            self.skipTest("curl lacks HTTP/2 support (nghttp2 required)")

        self.workdir = tempfile.mkdtemp(prefix="apex-grpc-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

        self.cert, self.key = make_certificate(self.workdir, "server")

        # Start gRPC backend server
        self.backend_port = free_port()
        self.backend = http.server.ThreadingHTTPServer(("127.0.0.1", self.backend_port), GrpcBackendHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()

        # Write Apex config
        self.listen_port = free_port()
        self.config_path = os.path.join(self.workdir, "apex.conf")
        config_content = f"""
http {{
    upstream grpc_backend {{
        server 127.0.0.1:{self.backend_port};
        keepalive 16;
    }}

    server {{
        listen "127.0.0.1:{self.listen_port}" tls;
        server_name localhost;

        tls {{
            certificate "{self.cert}";
            private_key "{self.key}";
        }}

        location "/" {{
            proxy_pass grpc_backend;
        }}
    }}
}}
"""
        with open(self.config_path, "w") as f:
            f.write(config_content)

        self.log_path = os.path.join(self.workdir, "apex.log")
        self.log_file = open(self.log_path, "ab")

        self.proc = subprocess.Popen([APEX, "-c", self.config_path],
                                     stdout=self.log_file, stderr=self.log_file)

        # Wait until ready
        ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.listen_port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        self.assertTrue(ready, "Apex failed to start")

    def tearDown(self):
        if hasattr(self, "backend"):
            self.backend.shutdown()
            self.backend.server_close()
        if hasattr(self, "proc") and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=STOP_TIMEOUT)
        if hasattr(self, "log_file") and not self.log_file.closed:
            self.log_file.close()

    def test_grpc_unary_with_trailers(self):
        url = f"https://127.0.0.1:{self.listen_port}/test.TestService/UnaryCall"
        req_msg = b"\x00\x00\x00\x00\x05World"

        # Execute curl over HTTP/2 with verbose output to inspect trailers
        result = subprocess.run(
            [
                "curl", "-v", "--silent", "--show-error", "--insecure", "--http2",
                "--output", "-",
                "-H", "Content-Type: application/grpc",
                "-H", "TE: trailers",
                "--data-binary", "@-",
                url,
            ],
            input=req_msg,
            capture_output=True, timeout=REQUEST_TIMEOUT,
        )
        stdout_text = result.stdout.decode("utf-8", "replace")
        stderr_text = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 0, f"curl failed: {result.stderr}")
        stderr = stderr_text

        # Verify HTTP/2 protocol used
        self.assertIn("HTTP/2 200", stderr, "Expected HTTP/2 200 status")
        self.assertIn("content-type: application/grpc", stderr.lower(), "Expected application/grpc content-type")

        # Verify trailers were received by client
        self.assertIn("grpc-status: 0", stderr.lower(), f"grpc-status trailer missing in stderr:\n{stderr}")
        self.assertIn("grpc-message: ok", stderr.lower(), f"grpc-message trailer missing in stderr:\n{stderr}")
        self.assertIn("x-custom-meta: apex-grpc-pass", stderr.lower(), f"custom metadata trailer missing in stderr:\n{stderr}")

        # Verify body received
        self.assertIn("Hello World", stdout_text, f"Expected response body payload; stdout={stdout_text!r}, stderr:\n{stderr}")

    def test_grpc_trailers_only(self):
        url = f"https://127.0.0.1:{self.listen_port}/test.TestService/TrailersOnly"

        result = subprocess.run(
            [
                "curl", "-v", "--silent", "--show-error", "--insecure", "--http2",
                "--output", "-",
                "-H", "Content-Type: application/grpc",
                "-H", "TE: trailers",
                "-X", "POST",
                url,
            ],
            capture_output=True, text=True, timeout=REQUEST_TIMEOUT,
        )

        self.assertEqual(result.returncode, 0, f"curl failed: {result.stderr}")
        stderr = result.stderr

        self.assertIn("HTTP/2 200", stderr, "Expected HTTP/2 200 status")
        self.assertIn("content-type: application/grpc", stderr.lower(), "Expected application/grpc content-type")
        self.assertIn("grpc-status: 16", stderr.lower(), f"grpc-status missing in trailers-only response:\n{stderr}")
        self.assertIn("grpc-message: unauthenticated", stderr.lower(), f"grpc-message missing in trailers-only response:\n{stderr}")

    def test_grpc_server_streaming(self):
        url = f"https://127.0.0.1:{self.listen_port}/test.TestService/ServerStreaming"
        req_msg = b"\x00\x00\x00\x00\x05Start"

        result = subprocess.run(
            [
                "curl", "-v", "--silent", "--show-error", "--insecure", "--http2",
                "--output", "-",
                "-H", "Content-Type: application/grpc",
                "-H", "TE: trailers",
                "--data-binary", "@-",
                url,
            ],
            input=req_msg,
            capture_output=True, timeout=REQUEST_TIMEOUT,
        )
        stdout_raw = result.stdout
        stderr_text = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 0, f"curl failed: {stderr_text}")
        self.assertIn("HTTP/2 200", stderr_text)
        self.assertIn("grpc-status: 0", stderr_text.lower())
        self.assertIn("x-stream-count: 5", stderr_text.lower())

        # Verify all 5 stream items are present in body
        for i in range(1, 6):
            expected = f"StreamItem-{i}".encode("ascii")
            self.assertIn(expected, stdout_raw, f"StreamItem-{i} missing from server-streaming output")

    def test_grpc_client_streaming(self):
        url = f"https://127.0.0.1:{self.listen_port}/test.TestService/ClientStreaming"
        # 3 length-prefixed messages in one request payload
        parts = [b"alpha", b"beta", b"gamma"]
        req_body = b""
        for p in parts:
            req_body += b"\x00" + len(p).to_bytes(4, "big") + p

        result = subprocess.run(
            [
                "curl", "-v", "--silent", "--show-error", "--insecure", "--http2",
                "--output", "-",
                "-H", "Content-Type: application/grpc",
                "-H", "TE: trailers",
                "--data-binary", "@-",
                url,
            ],
            input=req_body,
            capture_output=True, timeout=REQUEST_TIMEOUT,
        )
        stdout_raw = result.stdout
        stderr_text = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 0, f"curl failed: {stderr_text}")
        self.assertIn("HTTP/2 200", stderr_text)
        self.assertIn("grpc-status: 0", stderr_text.lower())
        self.assertIn("x-items-received: 3", stderr_text.lower())
        self.assertIn(b"Received 3 items: alpha,beta,gamma", stdout_raw)

    def test_grpc_bidi_streaming(self):
        url = f"https://127.0.0.1:{self.listen_port}/test.TestService/BidiStreaming"
        pings = [b"Apple", b"Banana", b"Cherry"]
        req_body = b""
        for p in pings:
            req_body += b"\x00" + len(p).to_bytes(4, "big") + p

        result = subprocess.run(
            [
                "curl", "-v", "--silent", "--show-error", "--insecure", "--http2",
                "--output", "-",
                "-H", "Content-Type: application/grpc",
                "-H", "TE: trailers",
                "--data-binary", "@-",
                url,
            ],
            input=req_body,
            capture_output=True, timeout=REQUEST_TIMEOUT,
        )
        stdout_raw = result.stdout
        stderr_text = result.stderr.decode("utf-8", "replace")

        self.assertEqual(result.returncode, 0, f"curl failed: {stderr_text}")
        self.assertIn("HTTP/2 200", stderr_text)
        self.assertIn("grpc-status: 0", stderr_text.lower())
        self.assertIn("x-pongs-sent: 3", stderr_text.lower())
        for p in pings:
            self.assertIn(b"Pong-" + p, stdout_raw)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[2:])
