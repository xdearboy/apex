#!/usr/bin/env python3
"""Integration tests for dynamic live compression (Zstd, Brotli, Gzip)
and distributed request tracing ($request_id) in Apex.

Covers:
- Dynamic on-the-fly Brotli compression (Accept-Encoding: br)
- Dynamic on-the-fly Zstandard compression (Accept-Encoding: zstd)
- Dynamic on-the-fly Gzip compression (Accept-Encoding: gzip)
- Priority algorithm negotiation (zstd > br > gzip)
- Minimum length threshold (gzip_min_length) bypass
- Non-eligible MIME type bypass
- Upstream already compressed bypass
- $request_id generation and header expansion
"""

import gzip
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

try:
    import brotli
except ImportError:
    brotli = None

try:
    import zstandard
except ImportError:
    zstandard = None

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SAMPLE_TEXT = "The quick brown fox jumps over the lazy dog. " * 30  # ~1350 bytes
SAMPLE_JSON = '{"message": "Hello from Apex proxy server! ' + ('a' * 1000) + '", "success": true}'


class TestCompression(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.upstream_port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.conf_path = os.path.join(self.temp_dir.name, "apex.conf")
        self.proc = None
        self.upstream_server = None
        self.upstream_thread = None
        self.upstream_running = False

    def tearDown(self):
        if self.proc is not None:
            if self.proc.poll() is None:
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
        if self.upstream_server:
            self.upstream_running = False
            try:
                self.upstream_server.close()
            except Exception:
                pass
            if self.upstream_thread:
                self.upstream_thread.join(timeout=2.0)
        self.temp_dir.cleanup()

    def start_mock_upstream(self):
        self.upstream_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.upstream_server.bind(("127.0.0.1", self.upstream_port))
        self.upstream_server.listen(10)
        self.upstream_running = True

        def run_loop():
            while self.upstream_running:
                try:
                    self.upstream_server.settimeout(0.5)
                    client, _ = self.upstream_server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    req_bytes = b""
                    while b"\r\n\r\n" not in req_bytes:
                        chunk = client.recv(1024)
                        if not chunk:
                            break
                        req_bytes += chunk

                    if b"/small" in req_bytes:
                        body = b"short"
                        hdr = (
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/plain\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        resp = hdr.encode("utf-8") + body
                    elif b"/image" in req_bytes:
                        body = b"\x89PNG\r\n\x1a\n" + (b"\x00" * 500)
                        hdr = (
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: image/png\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        resp = hdr.encode("utf-8") + body
                    elif b"/preencoded" in req_bytes:
                        gz_body = gzip.compress(SAMPLE_TEXT.encode("utf-8"))
                        hdr = (
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/plain\r\n"
                            f"Content-Encoding: gzip\r\n"
                            f"Content-Length: {len(gz_body)}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        resp = hdr.encode("utf-8") + gz_body
                    elif b"/json" in req_bytes:
                        body = SAMPLE_JSON.encode("utf-8")
                        hdr = (
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: application/json; charset=utf-8\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        resp = hdr.encode("utf-8") + body
                    else:
                        body = SAMPLE_TEXT.encode("utf-8")
                        hdr = (
                            f"HTTP/1.1 200 OK\r\n"
                            f"Content-Type: text/plain\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        resp = hdr.encode("utf-8") + body
                    client.sendall(resp)
                except Exception:
                    pass
                finally:
                    client.close()

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
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Apex failed to start")

    def raw_request(self, path="/", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        req_headers = headers or {}
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, resp_headers, data

    def test_dynamic_brotli_compression(self):
        if brotli is None:
            self.skipTest("brotli python module not available")

        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    zstd on;
    gzip_min_length 100;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/json", {"Accept-Encoding": "br"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "br")
        self.assertIn("accept-encoding", headers.get("vary", "").lower())
        decompressed = brotli.decompress(body).decode("utf-8")
        self.assertEqual(decompressed, SAMPLE_JSON)
        self.assertLess(len(body), len(SAMPLE_JSON))

    def test_dynamic_zstd_compression(self):
        if zstandard is None:
            self.skipTest("zstandard python module not available")

        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    zstd on;
    gzip_min_length 100;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/text", {"Accept-Encoding": "zstd"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "zstd")
        self.assertIn("accept-encoding", headers.get("vary", "").lower())
        dctx = zstandard.ZstdDecompressor()
        decompressed = dctx.decompress(body).decode("utf-8")
        self.assertEqual(decompressed, SAMPLE_TEXT)
        self.assertLess(len(body), len(SAMPLE_TEXT))

    def test_dynamic_gzip_compression(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    gzip_min_length 100;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/text", {"Accept-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "gzip")
        self.assertIn("accept-encoding", headers.get("vary", "").lower())
        decompressed = gzip.decompress(body).decode("utf-8")
        self.assertEqual(decompressed, SAMPLE_TEXT)
        self.assertLess(len(body), len(SAMPLE_TEXT))

    def test_priority_negotiation_zstd_preferred(self):
        if zstandard is None:
            self.skipTest("zstandard python module not available")

        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    zstd on;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/text", {"Accept-Encoding": "gzip, deflate, br, zstd"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "zstd")

    def test_priority_negotiation_brotli_over_gzip(self):
        if brotli is None:
            self.skipTest("brotli python module not available")

        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/text", {"Accept-Encoding": "gzip, deflate, br"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "br")

    def test_min_length_threshold_bypassed(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    gzip_min_length 500;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/small", {"Accept-Encoding": "gzip, deflate, br, zstd"})
        self.assertEqual(status, 200)
        self.assertNotIn("content-encoding", headers)
        self.assertEqual(body, b"short")

    def test_non_compressible_mime_type_bypassed(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    zstd on;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/image", {"Accept-Encoding": "gzip, deflate, br, zstd"})
        self.assertEqual(status, 200)
        self.assertNotIn("content-encoding", headers)
        self.assertTrue(body.startswith(b"\x89PNG"))

    def test_already_compressed_upstream_bypassed(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    gzip on;
    brotli on;
    zstd on;
    server {{
        listen {self.port};
        server_name localhost;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status, headers, body = self.raw_request("/preencoded", {"Accept-Encoding": "zstd, br, gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "gzip")
        decompressed = gzip.decompress(body).decode("utf-8")
        self.assertEqual(decompressed, SAMPLE_TEXT)

    def test_request_id_tracing(self):
        self.start_mock_upstream()
        conf = f"""
http {{
    server {{
        listen {self.port};
        server_name localhost;
        add_header X-Request-ID "$request_id" always;
        location / {{
            proxy_pass http://127.0.0.1:{self.upstream_port};
        }}
    }}
}}
"""
        self.start_apex(conf)
        status1, headers1, _ = self.raw_request("/text")
        self.assertEqual(status1, 200)
        req_id1 = headers1.get("x-request-id")
        self.assertIsNotNone(req_id1)
        self.assertEqual(len(req_id1), 32)
        int(req_id1, 16)  # Verify valid hexadecimal

        status2, headers2, _ = self.raw_request("/text")
        self.assertEqual(status2, 200)
        req_id2 = headers2.get("x-request-id")
        self.assertIsNotNone(req_id2)
        self.assertEqual(len(req_id2), 32)
        int(req_id2, 16)

        # Each request must have a distinct UUID/hex identifier
        self.assertNotEqual(req_id1, req_id2)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if not a.startswith("/") and not a.startswith("./")])
