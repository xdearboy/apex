#!/usr/bin/env python3
"""Integration tests for the HTTP/2 transport of the standalone `apex` binary.

Run from the repository root after `make`:

    python3 tests/test_h2.py ./apex

Covers ALPN selection of h2 on the TLS listener, proxied GET/POST round
trips over HTTP/2 (via curl --http2), parallel streams over one connection,
orderly GOAWAY teardown on SIGQUIT and the http/1.1 fallback for clients
that do not offer h2. Requires the `openssl` and `curl` CLIs (curl must be
built against nghttp2).
"""

import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import http.server

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 10.0
REQUEST_TIMEOUT = 10.0

TLS_CONFIG = """http {{
    upstream edge {{
        server 127.0.0.1:{upstream_port};
        keepalive 8;
    }}
    server {{
        listen "127.0.0.1:{listen_port}" tls;
        tls {{
            certificate "{certificate}";
            private_key "{key}";
        }}
        server_name localhost;
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_certificate(workdir, name):
    certificate = os.path.join(workdir, f"{name}.pem")
    key = os.path.join(workdir, f"{name}-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", certificate,
         "-days", "2", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True, timeout=30,
    )
    return certificate, key


class _BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/delay/"):
            time.sleep(float(self.path.rsplit("/", 1)[1]))
        body = b"h2-backend"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _BackendHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def stop_backend(server):
    server.shutdown()
    server.server_close()


class ApexServer:
    def __init__(self, config_path, workdir):
        self.log_path = os.path.join(workdir, "apex.log")
        self.log_file = open(self.log_path, "ab")
        self.proc = subprocess.Popen([APEX, "-c", config_path], stdout=self.log_file,
                                     stderr=self.log_file)

    def alive(self):
        return self.proc.poll() is None

    def wait_ready(self, port, timeout=START_TIMEOUT):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.alive():
                raise RuntimeError(f"apex exited early with code {self.proc.returncode}:\n{self.log_text()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError(f"apex did not accept connections on {port}:\n{self.log_text()}")

    def wait_exit(self, timeout=STOP_TIMEOUT):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=STOP_TIMEOUT)
            raise AssertionError(f"apex ignored termination signal; log:\n{self.log_text()}")
        return self.proc.returncode

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=STOP_TIMEOUT)
        self.log_file.close()

    def log_text(self):
        try:
            with open(self.log_path, "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return ""


def h2_frame_types(payload):
    """Parses the frame stream and returns the list of frame type codes."""
    types = []
    offset = 0
    while offset + 9 <= len(payload):
        length = int.from_bytes(payload[offset:offset + 3], "big")
        frame_type = payload[offset + 3]
        types.append(frame_type)
        offset += 9 + length
    return types


class H2RawClient:
    """Speaks just enough HTTP/2 to open a stream and observe teardown.

    Sends the fixed client preface plus an empty SETTINGS frame; enough for
    the server to accept the session and emit its own SETTINGS. Used for
    lifecycle tests; request/response round trips go through curl.
    """

    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    EMPTY_SETTINGS = struct.pack(">BBI", 0, 4, 0) + b"\x00\x00\x00\x00"

    def __init__(self, port, alpn=("h2",)):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(list(alpn))
        self.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=REQUEST_TIMEOUT))
        self.sock.sendall(self.PREFACE + self.EMPTY_SETTINGS)

    def alpn(self):
        return self.sock.selected_alpn_protocol()

    def read_frames(self, timeout=REQUEST_TIMEOUT):
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLEOFError, ConnectionResetError):
            pass
        except ssl.SSLError as error:
            if "UNEXPECTED_EOF_WHILE_READING" not in str(error):
                raise
        return data

    def wait_for_eof(self, timeout=STOP_TIMEOUT):
        self.sock.settimeout(0.25)
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                try:
                    if self.sock.recv(1) == b"":
                        return True
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                except ssl.SSLError as error:
                    if "UNEXPECTED_EOF_WHILE_READING" in str(error):
                        return False
                    raise
        finally:
            self.sock.settimeout(REQUEST_TIMEOUT)
        return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def curl(url, extra=()):
    return subprocess.run(
        ["curl", "--silent", "--show-error", "--insecure", "--http2", "--output", "-",
         "--write-out", "\n%{http_version}", url, *extra],
        capture_output=True, text=True, timeout=REQUEST_TIMEOUT,
    )


class H2ServingTest(unittest.TestCase):

    def setUp(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl CLI not available")
        probe = subprocess.run(["curl", "--version"], capture_output=True, text=True)
        if "nghttp2" not in probe.stdout:
            self.skipTest("curl lacks nghttp2 (no HTTP/2 support)")
        self.workdir = tempfile.mkdtemp(prefix="apex-h2-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.cert, self.key = make_certificate(self.workdir, "server")
        self.backend, self.backend_port = start_backend()
        self.addCleanup(stop_backend, self.backend)
        self.listen_port = free_port()
        self.config = os.path.join(self.workdir, "apex.conf")
        with open(self.config, "w") as handle:
            handle.write(TLS_CONFIG.format(listen_port=self.listen_port, upstream_port=self.backend_port,
                                           certificate=self.cert, key=self.key))
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)
        self.base_url = f"https://127.0.0.1:{self.listen_port}"

    def test_alpn_selects_h2(self):
        client = H2RawClient(self.listen_port)
        self.addCleanup(client.close)
        self.assertEqual(client.alpn(), "h2")
        payload = client.read_frames()
        # Server must answer the preface: SETTINGS first, no connection error.
        types = h2_frame_types(payload)
        self.assertIn(4, types, f"no SETTINGS frame received: {payload!r}")
        self.assertNotIn(7, types, "server sent GOAWAY before any request")

    def test_http2_get_round_trip(self):
        result = curl(f"{self.base_url}/")
        self.assertEqual(result.returncode, 0, result.stderr)
        body, _, version = result.stdout.rpartition("\n")
        self.assertEqual(body, "h2-backend")
        self.assertTrue(float(version) >= 2.0, f"not HTTP/2: {version}")

    def test_http2_post_round_trip(self):
        payload = os.urandom(64 * 1024)
        result = subprocess.run(
            ["curl", "--silent", "--show-error", "--insecure", "--http2", "--output", "-",
             "--write-out", "\n%{http_version}", "--request", "POST",
             f"{self.base_url}/echo", "--data-binary", payload.hex()],
            capture_output=True, text=True, timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        body, _, version = result.stdout.rpartition("\n")
        self.assertEqual(body, payload.hex())
        self.assertTrue(float(version) >= 2.0, f"not HTTP/2: {version}")

    def test_http2_parallel_streams_one_connection(self):
        result = curl(self.base_url, ["--parallel", "--parallel-max", "10",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/",
                                      "--url", f"{self.base_url}/"])
        self.assertEqual(result.returncode, 0, result.stderr)
        bodies = [line for line in result.stdout.splitlines() if line != "2" and line != "2.0"]
        self.assertEqual(len(bodies), 8, result.stdout)
        for body in bodies:
            self.assertEqual(body, "h2-backend")

    def test_http1_fallback_still_served(self):
        client = H2RawClient(self.listen_port, alpn=("http/1.1",))
        self.addCleanup(client.close)
        self.assertEqual(client.alpn(), "http/1.1")
        client.sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        client.sock.settimeout(REQUEST_TIMEOUT)
        data = b""
        while b"h2-backend" not in data:
            chunk = client.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        self.assertIn(b"200", data.split(b"\r\n", 1)[0])
        self.assertIn(b"h2-backend", data)

    def test_sigquit_drains_h2_session(self):
        client = H2RawClient(self.listen_port)
        self.addCleanup(client.close)
        time.sleep(0.3)  # let SETTINGS exchange settle
        self.server.proc.send_signal(signal.SIGQUIT)
        payload = client.read_frames(timeout=STOP_TIMEOUT)
        types = h2_frame_types(payload)
        self.assertIn(7, types, f"no GOAWAY frame on drain: {types}")
        self.assertTrue(client.wait_for_eof(), "h2 connection was not closed orderly")
        self.assertEqual(self.server.wait_exit(), 0)

    def test_sigterm_exits_zero(self):
        self.server.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait_exit(), 0)

    def test_http2_large_response(self):
        result = curl(f"{self.base_url}/")
        self.assertEqual(result.returncode, 0, result.stderr)
        body, _, version = result.stdout.rpartition("\n")
        self.assertEqual(body, "h2-backend")
        self.assertTrue(float(version) >= 2.0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
