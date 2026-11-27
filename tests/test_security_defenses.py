import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = sys.argv[1] if len(sys.argv) > 1 else "./apex"

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 0))
        return s.getsockname()[1]

class TestSecurityDefenses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.dummy_port = find_free_port()
        cls.static_dir = tempfile.mkdtemp(prefix="apex-test-static-")
        with open(os.path.join(cls.static_dir, "test.txt"), "w") as f:
            f.write("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        with open(os.path.join(cls.static_dir, "empty.txt"), "w") as f:
            pass

        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    upstream dummy_pool {{
        server 127.0.0.1:{cls.dummy_port};
    }}

    server {{
        listen {cls.port};
        server_name localhost;

        location /static/ {{
            root {cls.static_dir};
        }}

        location /api/ {{
            api write=on;
        }}

        location / {{
            return 200 "OK\\n";
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.static_dir, ignore_errors=True)

    def _raw_exchange(self, raw_bytes):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2.0) as s:
            s.sendall(raw_bytes)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("latin1")

    def test_01_cl_te_smuggling_rejected(self):
        """RFC 9112 Section 6.1: Both Content-Length and Transfer-Encoding chunked must be rejected with 400."""
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 6\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"0\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("400 Bad Request", resp)
        self.assertIn("Connection: close", resp)

    def test_02_conflicting_content_length_rejected(self):
        """RFC 9112 Section 5.2: Multiple conflicting Content-Length headers must be rejected with 400."""
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Length: 10\r\n"
            b"Connection: close\r\n\r\n"
            b"hello"
        )
        resp = self._raw_exchange(req)
        self.assertIn("400 Bad Request", resp)

    def test_03_malformed_content_length_rejected(self):
        """Invalid non-digit characters in Content-Length must be rejected with 400."""
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 5xyz\r\n"
            b"Connection: close\r\n\r\n"
            b"hello"
        )
        resp = self._raw_exchange(req)
        self.assertIn("400 Bad Request", resp)

    def test_04_legitimate_chunked_body_succeeds(self):
        """Valid chunked body is parsed and decoded properly."""
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("200 OK", resp)

    def test_05_standard_http11_request_succeeds(self):
        """Standard HTTP/1.1 request operates normally."""
        req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("200 OK", resp)
        self.assertIn("OK\n", resp)

    def test_06_malformed_range_ignored_rfc9110(self):
        """RFC 9110 Section 14.2: Syntactically invalid Range must be ignored and return 200 OK with full representation."""
        req = (
            b"GET /static/test.txt HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Range: bytes=foo-bar\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("200 OK", resp)
        self.assertNotIn("206 Partial Content", resp)
        self.assertIn("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", resp)

    def test_07_valid_range_returns_206(self):
        """Valid Range returns 206 Partial Content with proper Content-Range."""
        req = (
            b"GET /static/test.txt HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Range: bytes=0-4\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("206 Partial Content", resp)
        self.assertIn("Content-Range: bytes 0-4/36", resp)
        self.assertIn("01234", resp)

    def test_08_out_of_bounds_range_returns_416(self):
        """Out-of-bounds Range returns 416 Range Not Satisfiable."""
        req = (
            b"GET /static/test.txt HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Range: bytes=100-200\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("416 Range Not Satisfiable", resp)

    def test_09_payload_too_large_returns_413(self):
        """RFC 9110 Section 15.5.14: Payload larger than server buffer must return 413 Payload Too Large."""
        req = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 104857600\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("413 Payload Too Large", resp)
        self.assertIn("Connection: close", resp)

    def test_10_headers_too_large_returns_431(self):
        """RFC 6585 Section 5: Headers exceeding buffer capacity must return 431 Request Header Fields Too Large."""
        giant_header = b"X-Big: " + (b"A" * 16500)
        req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n" +
            giant_header
        )
        resp = self._raw_exchange(req)
        self.assertIn("431 Request Header Fields Too Large", resp)
        self.assertIn("Connection: close", resp)

    def test_15_if_range_strong_etag_match_returns_206(self):
        """RFC 9110 Section 13.1.5: Matching strong ETag in If-Range returns 206 Partial Content."""
        resp = self._raw_exchange(b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        etag = None
        for line in resp.splitlines():
            if line.lower().startswith("etag:"):
                etag = line.split(":", 1)[1].strip()
                break
        self.assertIsNotNone(etag, "ETag not present in response")

        req = (
            f"GET /static/test.txt HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"If-Range: {etag}\r\n"
            f"Range: bytes=0-4\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")
        part_resp = self._raw_exchange(req)
        self.assertIn("206 Partial Content", part_resp)
        self.assertIn("Content-Range: bytes 0-4/36", part_resp)
        self.assertIn("01234", part_resp)

    def test_16_if_range_etag_mismatch_returns_200(self):
        """RFC 9110 Section 13.1.5: Mismatched ETag in If-Range causes Range to be ignored, returning 200 OK with full representation."""
        req = (
            b"GET /static/test.txt HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b'If-Range: "stale-mismatched-etag"\r\n'
            b"Range: bytes=0-4\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("200 OK", resp)
        self.assertNotIn("206 Partial Content", resp)
        self.assertIn("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", resp)

    def test_17_if_range_weak_etag_returns_200(self):
        """RFC 9110 Section 13.1.5: Weak entity tag (W/\"...\") MUST NOT match for If-Range, returning 200 OK with full representation."""
        resp = self._raw_exchange(b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        etag = None
        for line in resp.splitlines():
            if line.lower().startswith("etag:"):
                etag = line.split(":", 1)[1].strip()
                break
        self.assertIsNotNone(etag)
        weak_etag = f"W/{etag}"

        req = (
            f"GET /static/test.txt HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"If-Range: {weak_etag}\r\n"
            f"Range: bytes=0-4\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")
        resp = self._raw_exchange(req)
        self.assertIn("200 OK", resp)
        self.assertNotIn("206 Partial Content", resp)
        self.assertIn("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", resp)

    def test_18_empty_file_suffix_range_returns_416(self):
        """RFC 9110 Section 14.1.2: Suffix-byte-range (bytes=-N) on empty (0-byte) representation is unsatisfiable (416)."""
        req = (
            b"GET /static/empty.txt HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Range: bytes=-5\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._raw_exchange(req)
        self.assertIn("416 Range Not Satisfiable", resp)
        self.assertIn("Content-Range: bytes */0", resp)

    def test_19_api_method_not_allowed_allow_headers(self):
        """RFC 9110 Section 15.5.6: 405 Method Not Allowed responses must include an Allow header listing permitted methods."""
        # 1. Collection endpoint allows GET, HEAD
        resp1 = self._raw_exchange(b"POST /api/http/upstreams HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertIn("405 Method Not Allowed", resp1)
        self.assertIn("Allow: GET, HEAD", resp1)

        # 2. Server collection endpoint allows GET, HEAD, POST
        resp2 = self._raw_exchange(b"PUT /api/http/upstreams/dummy_pool/servers HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertIn("405 Method Not Allowed", resp2)
        self.assertIn("Allow: GET, HEAD, POST", resp2)

        # 3. Individual server endpoint allows PATCH, DELETE
        resp3 = self._raw_exchange(f"GET /api/http/upstreams/dummy_pool/servers/127.0.0.1:{self.dummy_port} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode("latin1"))
        self.assertIn("405 Method Not Allowed", resp3)
        self.assertIn("Allow: PATCH, DELETE", resp3)



class TestTlsDualProtocols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="apex-test-tls-")
        cls.cert = os.path.join(cls.workdir, "cert.pem")
        cls.key = os.path.join(cls.workdir, "key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", cls.key, "-out", cls.cert,
             "-days", "1", "-nodes", "-subj", "/CN=localhost"],
            check=True, capture_output=True
        )

        cls.port = find_free_port()
        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    server {{
        listen {cls.port} tls;
        server_name localhost;
        tls {{
            certificate "{cls.cert}";
            private_key "{cls.key}";
            protocols TLSv1.2 TLSv1.3;
        }}
        location / {{
            return 200 "OK\\n";
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex TLS server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_11_tls12_client_handshake_succeeds(self):
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", self.port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                self.assertEqual(ssock.version(), "TLSv1.2")
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                resp = ssock.recv(1024)
                self.assertIn(b"200 OK", resp)

    def test_12_tls13_client_handshake_succeeds(self):
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection(("127.0.0.1", self.port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                self.assertEqual(ssock.version(), "TLSv1.3")
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                resp = ssock.recv(1024)
                self.assertIn(b"200 OK", resp)


class TestRealIpConfigValidation(unittest.TestCase):
    def test_13_trailing_slash_cidr_rejected(self):
        """Invalid CIDR with empty prefix after slash (e.g. 10.0.0.0/) must fail config validation."""
        port = find_free_port()
        bad_conf = f"""
events {{ worker_connections 1024; }}
http {{
    set_real_ip_from 10.0.0.0/;
    server {{
        listen {port};
        location / {{ return 200 "OK\\n"; }}
    }}
}}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(bad_conf)
            f.flush()
            conf_path = f.name
        try:
            res = subprocess.run([APEX, "-t", "-c", conf_path], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("invalid IP or CIDR", res.stderr)
        finally:
            try:
                os.unlink(conf_path)
            except OSError:
                pass


class TestRateLimiting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.static_dir = tempfile.mkdtemp(prefix="apex-test-ratelimit-")
        with open(os.path.join(cls.static_dir, "index.html"), "w") as f:
            f.write("allowed\n")

        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    limit_req_zone $remote_addr zone=api_limit:10m rate=1r/s;

    server {{
        listen {cls.port};
        server_name localhost;

        location / {{
            root {cls.static_dir};
            limit_req zone=api_limit burst=2 nodelay;
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex rate-limiting server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.static_dir, ignore_errors=True)

    def _get(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2.0) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("latin1")

    def test_14_rate_limit_burst_and_rejection(self):
        """Initial capacity (1.0 + burst 2 = 3) succeeds; 4th rapid request is rejected with 503 and Retry-After."""
        r1 = self._get()
        r2 = self._get()
        r3 = self._get()
        r4 = self._get()

        self.assertIn("200 OK", r1)
        self.assertIn("200 OK", r2)
        self.assertIn("200 OK", r3)
        self.assertIn("503 Service Unavailable", r4)
        self.assertIn("Retry-After:", r4)


class TestRfcCacheAndCompression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.backend_sock.bind(("127.0.0.1", 0))
        cls.backend_port = cls.backend_sock.getsockname()[1]
        cls.backend_sock.listen(128)
        cls.backend_running = True

        def backend_worker():
            while cls.backend_running:
                try:
                    conn, _ = cls.backend_sock.accept()
                except OSError:
                    break
                try:
                    req = b""
                    while b"\r\n\r\n" not in req:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        req += chunk
                    body = b"The quick brown fox jumps over the lazy dog! 0123456789"
                    resp = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/plain\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("latin1") + body
                    conn.sendall(resp)
                except Exception:
                    pass
                finally:
                    conn.close()

        cls.backend_thread = threading.Thread(target=backend_worker, daemon=True)
        cls.backend_thread.start()

        cls.port = find_free_port()
        cls.cache_dir = tempfile.mkdtemp(prefix="apex-test-rfccache-")
        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    proxy_cache_path {cls.cache_dir} levels=1:2 keys_zone=rfc_cache:10m max_size=50m inactive=10m;
    gzip on;
    gzip_min_length 10;
    gzip_types text/plain;

    upstream rfc_backend {{
        server 127.0.0.1:{cls.backend_port};
    }}

    server {{
        listen {cls.port};
        server_name localhost;

        location /cached/ {{
            proxy_pass http://rfc_backend;
            proxy_cache rfc_cache;
            proxy_cache_valid 200 10m;
        }}

        location /compress/ {{
            proxy_pass http://rfc_backend;
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex cache & compress server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.backend_running = False
        try:
            cls.backend_sock.close()
        except OSError:
            pass
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.cache_dir, ignore_errors=True)

    def _exchange(self, req_bytes):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as s:
            s.sendall(req_bytes)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("latin1")

    def test_20_accept_encoding_q0_disables_gzip(self):
        """RFC 9110 Section 12.5.3: Accept-Encoding q=0 explicitly disables the algorithm."""
        # 1. q=0 disables gzip
        req_q0 = (
            b"GET /compress/ HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Accept-Encoding: gzip;q=0, identity\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp_q0 = self._exchange(req_q0)
        self.assertIn("200 OK", resp_q0)
        self.assertNotIn("Content-Encoding: gzip", resp_q0)

        # 2. Normal Accept-Encoding gzip enables gzip
        req_normal = (
            b"GET /compress/ HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Accept-Encoding: gzip\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp_normal = self._exchange(req_normal)
        self.assertIn("200 OK", resp_normal)
        self.assertIn("Content-Encoding: gzip", resp_normal)

    def test_21_cache_hit_contains_age_header(self):
        """RFC 9111 Section 5.1: Caches must generate an Age header field on cache hits."""
        req = b"GET /cached/item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        resp1 = self._exchange(req)
        self.assertIn("200 OK", resp1)
        self.assertIn("X-Cache: MISS", resp1)

        time.sleep(1.0)

        resp2 = self._exchange(req)
        self.assertIn("200 OK", resp2)
        self.assertIn("X-Cache: HIT", resp2)
        self.assertIn("Age: ", resp2)

        age_val = None
        for line in resp2.splitlines():
            if line.lower().startswith("age:"):
                age_val = int(line.split(":", 1)[1].strip())
                break
        self.assertIsNotNone(age_val)
        self.assertGreaterEqual(age_val, 1)


class TestH2SecurityDefenses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="apex-test-h2-defenses-")
        cls.cert = os.path.join(cls.workdir, "cert.pem")
        cls.key = os.path.join(cls.workdir, "key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", cls.key, "-out", cls.cert,
             "-days", "1", "-nodes", "-subj", "/CN=localhost"],
            check=True, capture_output=True
        )
        cls.port = find_free_port()
        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    server {{
        listen {cls.port} tls;
        server_name localhost;
        tls {{
            certificate "{cls.cert}";
            private_key "{cls.key}";
            protocols TLSv1.3;
        }}
        location / {{
            return 200 "OK\\n";
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex H2 server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_22_h2_rapid_reset_flood_mitigated(self):
        """CVE-2023-44487 Rapid Reset: Flooding server with >128 RST_STREAM frames triggers GOAWAY / connection closure."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname="localhost") as s:
                self.assertEqual(s.selected_alpn_protocol(), "h2")
                PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                EMPTY_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
                s.sendall(PREFACE + EMPTY_SETTINGS)

                burst = b""
                for i in range(1, 141):
                    stream_id = (i * 2) - 1
                    header = (4).to_bytes(3, "big") + b"\x03\x00" + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
                    payload = (8).to_bytes(4, "big")
                    burst += header + payload

                s.sendall(burst)

                received = b""
                s.settimeout(2.0)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        received += chunk
                except (socket.timeout, ssl.SSLWantReadError, ssl.SSLEOFError, ConnectionResetError):
                    pass

                has_goaway = False
                idx = 0
                while idx + 9 <= len(received):
                    flen = int.from_bytes(received[idx:idx+3], "big")
                    ftype = received[idx+3]
                    if ftype == 7:
                        has_goaway = True
                        break
                    idx += 9 + flen

                self.assertTrue(has_goaway or len(received) == 0 or s.fileno() == -1)


class TestPhase4RfcAndSmuggling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="apex-test-p4-")
        cls.static_dir = os.path.join(cls.workdir, "static")
        os.makedirs(cls.static_dir, exist_ok=True)
        cls.test_file_path = os.path.join(cls.static_dir, "test.txt")
        with open(cls.test_file_path, "wb") as f:
            f.write(b"Hello RFC 9110 Preconditions and Hardening!")

        cls.upstream_requests = []
        cls.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.upstream_sock.bind(("127.0.0.1", 0))
        cls.upstream_port = cls.upstream_sock.getsockname()[1]
        cls.upstream_sock.listen(128)
        cls.upstream_running = True

        def upstream_worker():
            while cls.upstream_running:
                try:
                    conn, _ = cls.upstream_sock.accept()
                except OSError:
                    break
                try:
                    raw_req = b""
                    while b"\r\n\r\n" not in raw_req:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        raw_req += chunk

                    header_part, rest = raw_req.split(b"\r\n\r\n", 1)
                    content_length = 0
                    for line in header_part.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            content_length = int(line.split(b":", 1)[1].strip())

                    while len(rest) < content_length:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        rest += chunk

                    full_req = header_part + b"\r\n\r\n" + rest
                    cls.upstream_requests.append(full_req)

                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: 13\r\n"
                        b"Proxy-Authenticate: Basic realm=test\r\n"
                        b"Connection: close, X-Upstream-Hop\r\n"
                        b"X-Upstream-Hop: upstream-secret\r\n"
                        b"\r\n"
                        b"mock-response"
                    )
                    conn.sendall(resp)
                except Exception:
                    pass
                finally:
                    conn.close()

        cls.upstream_thread = threading.Thread(target=upstream_worker, daemon=True)
        cls.upstream_thread.start()

        cls.port = find_free_port()
        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    upstream test_upstream {{
        server 127.0.0.1:{cls.upstream_port};
    }}

    server {{
        listen {cls.port};
        server_name localhost;

        location /static/ {{
            root {cls.static_dir};
        }}

        location /proxy/ {{
            proxy_pass http://test_upstream;
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex Phase 4 server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.upstream_running = False
        try:
            cls.upstream_sock.close()
        except OSError:
            pass
        try:
            os.unlink(cls.conf_file.name)
        except OSError:
            pass
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _exchange(self, req_bytes):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as s:
            s.sendall(req_bytes)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("latin1")

    def _get_static_headers(self):
        resp = self._exchange(b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        headers = {}
        header_part = resp.split("\r\n\r\n", 1)[0]
        for line in header_part.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def test_23_if_match_success_returns_200(self):
        """RFC 9110 §13.2.2 Step 1: If-Match with valid ETag succeeds with 200 OK."""
        headers = self._get_static_headers()
        etag = headers.get("etag")
        self.assertIsNotNone(etag)
        req = f"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-Match: {etag}\r\nConnection: close\r\n\r\n".encode("latin1")
        resp = self._exchange(req)
        self.assertIn("200 OK", resp)
        self.assertIn("Hello RFC 9110", resp)

    def test_24_if_match_failure_returns_412(self):
        """RFC 9110 §13.2.2 Step 1: If-Match with mismatched ETag returns 412 Precondition Failed."""
        req = b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-Match: \"wrong-etag-12345\"\r\nConnection: close\r\n\r\n"
        resp = self._exchange(req)
        self.assertIn("412 Precondition Failed", resp)

    def test_25_if_unmodified_since_failure_returns_412(self):
        """RFC 9110 §13.2.2 Step 2: If-Unmodified-Since in the past returns 412 Precondition Failed."""
        req = b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\n"
        resp = self._exchange(req)
        self.assertIn("412 Precondition Failed", resp)

    def test_26_if_none_match_weak_etag_returns_304(self):
        """RFC 9110 §13.2.2 Step 3: If-None-Match with weak tag matches strong representation and returns 304."""
        headers = self._get_static_headers()
        etag = headers.get("etag")
        self.assertIsNotNone(etag)
        weak_etag = f"W/{etag}" if not etag.startswith("W/") else etag
        req = f"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {weak_etag}\r\nConnection: close\r\n\r\n".encode("latin1")
        resp = self._exchange(req)
        self.assertIn("304 Not Modified", resp)

    def test_27_if_none_match_list_returns_304(self):
        """RFC 9110 §13.2.2 Step 3: Comma-separated list containing valid ETag returns 304 Not Modified."""
        headers = self._get_static_headers()
        etag = headers.get("etag")
        self.assertIsNotNone(etag)
        req = f"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"random-tag-1\", {etag}, \"random-tag-2\"\r\nConnection: close\r\n\r\n".encode("latin1")
        resp = self._exchange(req)
        self.assertIn("304 Not Modified", resp)

    def test_28_if_none_match_takes_precedence_over_if_modified_since(self):
        """RFC 9110 §13.2.2 Step 3->4: If-None-Match mismatch skips If-Modified-Since and returns 200 OK."""
        future_date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
        req = f"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"wrong-etag\"\r\nIf-Modified-Since: {future_date}\r\nConnection: close\r\n\r\n".encode("latin1")
        resp = self._exchange(req)
        self.assertIn("200 OK", resp)
        self.assertIn("Hello RFC 9110", resp)

    def test_29_head_error_returns_no_body(self):
        """RFC 9110 §9.3.5: HEAD request on error route emits Content-Length but zero body bytes."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as s:
            s.sendall(b"HEAD /nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            raw_resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
        self.assertIn(b"404 Not Found", raw_resp)
        self.assertIn(b"Content-Length: ", raw_resp)
        header_part, body_part = raw_resp.split(b"\r\n\r\n", 1)
        self.assertEqual(len(body_part), 0)

    def test_30_chunked_client_request_upstream_strips_te(self):
        """RFC 9112 §6.1: Chunked client request forwarded to upstream backend has Transfer-Encoding stripped and pure Content-Length."""
        req = (
            b"POST /proxy/submit HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"b\r\nhello world\r\n"
            b"0\r\n\r\n"
        )
        resp = self._exchange(req)
        self.assertIn("200 OK", resp)
        self.assertTrue(len(self.upstream_requests) > 0)
        last_upstream_req = self.upstream_requests[-1]
        up_header, up_body = last_upstream_req.split(b"\r\n\r\n", 1)
        up_header_str = up_header.decode("latin1")

        self.assertNotIn("Transfer-Encoding", up_header_str)
        self.assertIn("Content-Length: 11", up_header_str)
        self.assertEqual(up_body, b"hello world")

    def test_31_hop_by_hop_headers_stripped(self):
        """RFC 9110 §7.6.1: Hop-by-hop headers and connection tokens stripped on upstream request and client response."""
        req = (
            b"GET /proxy/hop HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Proxy-Authenticate: Basic realm=test\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"Connection: close, X-Client-Hop\r\n"
            b"X-Client-Hop: client-secret\r\n\r\n"
        )
        client_resp = self._exchange(req)
        self.assertIn("200 OK", client_resp)
        last_upstream_req = self.upstream_requests[-1]
        up_header_str = last_upstream_req.split(b"\r\n\r\n", 1)[0].decode("latin1")

        # Client -> Upstream stripping
        self.assertNotIn("Proxy-Authenticate", up_header_str)
        self.assertNotIn("Proxy-Connection", up_header_str)
        self.assertNotIn("X-Client-Hop", up_header_str)

        # Upstream -> Client stripping
        self.assertNotIn("Proxy-Authenticate", client_resp)
        self.assertNotIn("X-Upstream-Hop", client_resp)


class TestPhase5LimitsAndPipelining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="apex_phase5_")
        cls.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.upstream_sock.bind(("127.0.0.1", 0))
        cls.upstream_port = cls.upstream_sock.getsockname()[1]
        cls.upstream_sock.listen(128)

        cls.upstream_requests = []
        cls.upstream_stop = False

        def upstream_worker():
            while not cls.upstream_stop:
                try:
                    cls.upstream_sock.settimeout(0.5)
                    conn, _ = cls.upstream_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    conn.settimeout(2.0)
                    raw_req = b""
                    while b"\r\n\r\n" not in raw_req:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        raw_req += chunk

                    if b"\r\n\r\n" in raw_req:
                        header_part, rest = raw_req.split(b"\r\n\r\n", 1)
                        content_length = 0
                        for line in header_part.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                content_length = int(line.split(b":", 1)[1].strip())

                        while len(rest) < content_length:
                            chunk = conn.recv(1024)
                            if not chunk:
                                break
                            rest += chunk

                        full_req = header_part + b"\r\n\r\n" + rest
                        cls.upstream_requests.append(full_req)

                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: 2\r\n"
                        b"\r\n"
                        b"OK"
                    )
                    conn.sendall(resp)
                except Exception:
                    pass
                finally:
                    conn.close()

        cls.upstream_thread = threading.Thread(target=upstream_worker, daemon=True)
        cls.upstream_thread.start()

        cls.static_dir = os.path.join(cls.workdir, "html")
        os.makedirs(cls.static_dir, exist_ok=True)
        with open(os.path.join(cls.static_dir, "hello.txt"), "w") as f:
            f.write("Hello World!\n")
        try:
            os.symlink("/etc/hosts", os.path.join(cls.static_dir, "symlink_escape"))
        except OSError:
            pass

        cls.port = find_free_port()
        cls.conf = f"""
events {{
    worker_connections 1024;
}}

http {{
    keepalive_requests 2;
    client_max_body_size 2k;

    upstream test_upstream {{
        server 127.0.0.1:{cls.upstream_port};
    }}

    server {{
        listen {cls.port};
        server_name localhost;

        location /static/ {{
            root {cls.static_dir};
        }}

        location /proxy/ {{
            proxy_pass http://test_upstream;
        }}

        location /limited/ {{
            client_max_body_size 500;
            proxy_pass http://test_upstream;
        }}

        location /unlimited/ {{
            client_max_body_size 0;
            proxy_pass http://test_upstream;
        }}
    }}
}}
"""
        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(cls.conf)
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + 5.0
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
            raise RuntimeError("Apex failed to start for TestPhase5LimitsAndPipelining")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait()
        cls.upstream_stop = True
        try:
            cls.upstream_sock.close()
        except OSError:
            pass
        cls.upstream_thread.join(timeout=1.0)
        try:
            os.remove(cls.conf_file.name)
            shutil.rmtree(cls.workdir, ignore_errors=True)
        except OSError:
            pass

    def _exchange_raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as s:
            s.sendall(data)
            chunks = []
            while True:
                try:
                    c = s.recv(4096)
                    if not c:
                        break
                    chunks.append(c)
                except socket.timeout:
                    break
            return b"".join(chunks)

    def test_32_obs_fold_rejection(self):
        """RFC 9112 §5.2: Obs-fold (leading space or tab on continuation line) rejected with 400 Bad Request."""
        req = (
            b"GET /proxy/test HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"X-Test: value\r\n"
            b"  folded continuation\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._exchange_raw(req)
        self.assertIn(b"400 Bad Request", resp)
        self.assertIn(b"Connection: close", resp)

    def test_33_pipelined_close_break(self):
        """RFC 9112 §9.6: Pipelining request with Connection: close followed by second request ignores the second and closes."""
        init_len = len(self.upstream_requests)
        req = (
            b"GET /proxy/first HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
            b"GET /proxy/second HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = self._exchange_raw(req)
        self.assertIn(b"200 OK", resp)
        # Should only have one response (the first one)
        self.assertEqual(resp.count(b"HTTP/1.1 200 OK"), 1)
        # Upstream backend should only have received the first request
        new_requests = self.upstream_requests[init_len:]
        self.assertEqual(len(new_requests), 1)
        self.assertIn(b"/proxy/first", new_requests[0])

    def test_34_keepalive_requests_recycling(self):
        """keepalive_requests 2: connection serves 2 requests, then closes with Connection: close."""
        def read_http_response(sock):
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return buf
                buf += chunk
            header_part, _, body_part = buf.partition(b"\r\n\r\n")
            cl = 0
            for line in header_part.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    cl = int(line.split(b":", 1)[1].strip())
                    break
            while len(body_part) < cl:
                chunk = sock.recv(cl - len(body_part))
                if not chunk:
                    break
                body_part += chunk
            return header_part + b"\r\n\r\n" + body_part

        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as s:
            # Request 1
            s.sendall(b"GET /proxy/req1 HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
            resp1 = read_http_response(s)
            self.assertIn(b"200 OK", resp1)
            self.assertIn(b"Connection: keep-alive", resp1)

            # Request 2 (the 2nd request, should reach keepalive_requests=2)
            s.sendall(b"GET /proxy/req2 HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
            resp2 = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp2 += chunk
            self.assertIn(b"200 OK", resp2)
            self.assertIn(b"Connection: close", resp2)

    def test_35_client_max_body_size_content_length(self):
        """client_max_body_size 2k: allows 1KB body (200 OK) and rejects 3KB body (413 Payload Too Large)."""
        # 1KB payload -> 200 OK
        body_1k = b"x" * 1024
        req_ok = (
            f"POST /proxy/upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: {len(body_1k)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body_1k
        resp_ok = self._exchange_raw(req_ok)
        self.assertIn(b"200 OK", resp_ok)

        # 3KB payload -> 413 Payload Too Large
        body_3k = b"x" * 3072
        req_too_large = (
            f"POST /proxy/upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: {len(body_3k)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body_3k
        resp_too_large = self._exchange_raw(req_too_large)
        self.assertIn(b"413 Payload Too Large", resp_too_large)
        self.assertIn(b"Connection: close", resp_too_large)

    def test_36_client_max_body_size_chunked(self):
        """client_max_body_size 2k: chunked transfer exceeding 2KB returns 413 Payload Too Large."""
        chunk1 = b"a" * 1500
        chunk2 = b"b" * 1500
        req_chunked = (
            b"POST /proxy/chunked HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"5dc\r\n" + chunk1 + b"\r\n"
            b"5dc\r\n" + chunk2 + b"\r\n"
            b"0\r\n\r\n"
        )
        resp = self._exchange_raw(req_chunked)
        self.assertIn(b"413 Payload Too Large", resp)
        self.assertIn(b"Connection: close", resp)

    def test_37_client_max_body_size_location_override(self):
        """location /limited/ has client_max_body_size 500: rejects 800-byte body and allows 300-byte body."""
        # 300-byte body to /limited/ -> 200 OK
        body_300 = b"y" * 300
        req_ok = (
            f"POST /limited/data HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: {len(body_300)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body_300
        resp_ok = self._exchange_raw(req_ok)
        self.assertIn(b"200 OK", resp_ok)

        # 800-byte body to /limited/ -> 413 Payload Too Large
        body_800 = b"y" * 800
        req_too_large = (
            f"POST /limited/data HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Length: {len(body_800)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body_800
        resp_too_large = self._exchange_raw(req_too_large)
        self.assertIn(b"413 Payload Too Large", resp_too_large)

    def test_38_static_symlink_escape_rejected(self):
        """Symlink pointing outside location root must be rejected with 403 Forbidden."""
        # Legitimate static file -> 200 OK
        resp_valid = self._exchange_raw(b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200 OK", resp_valid)
        self.assertIn(b"Hello World!", resp_valid)

        # Symlink pointing to /etc/hosts -> 403 Forbidden
        resp_symlink = self._exchange_raw(b"GET /static/symlink_escape HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertIn(b"403 Forbidden", resp_symlink)

    def test_39_static_prefix_confusion_rejected(self):
        """Location /static/ prefix must not match /static_secret and must return 404 Not Found."""
        resp = self._exchange_raw(b"GET /static_secret/secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        self.assertIn(b"404 Not Found", resp)

    def test_40_whitespace_before_colon_rejected(self):
        """RFC 9112 §5.1: Space or tab before header field colon rejected with 400 Bad Request."""
        req = b"GET /proxy/test HTTP/1.1\r\nHost: localhost\r\nX-Custom-Header : bad_value\r\nConnection: close\r\n\r\n"
        resp = self._exchange_raw(req)
        self.assertIn(b"400 Bad Request", resp)
        self.assertIn(b"Connection: close", resp)

    def test_41_signed_content_length_rejected(self):
        """RFC 9110 §8.6: Signed Content-Length (+5 or -5) rejected with 400 Bad Request."""
        req = b"POST /proxy/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: +5\r\nConnection: close\r\n\r\nhello"
        resp = self._exchange_raw(req)
        self.assertIn(b"400 Bad Request", resp)
        self.assertIn(b"Connection: close", resp)

    def test_42_invalid_chunk_size_leading_sign_rejected(self):
        """RFC 9112 §7.1: Leading sign in chunk-size (+5) rejected with 400 Bad Request."""
        req = (
            b"POST /proxy/chunked HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"+5\r\n"
            b"hello\r\n"
            b"0\r\n\r\n"
        )
        resp = self._exchange_raw(req)
        self.assertIn(b"400 Bad Request", resp)
        self.assertIn(b"Connection: close", resp)

    def test_43_transfer_encoding_not_final_chunked_rejected(self):
        """RFC 9112 §6.3: Transfer-Encoding where chunked is not final coding rejected with 400 Bad Request."""
        req = (
            b"POST /proxy/chunked HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked, gzip\r\n"
            b"Connection: close\r\n\r\n"
            b"0\r\n\r\n"
        )
        resp = self._exchange_raw(req)
        self.assertIn(b"400 Bad Request", resp)
        self.assertIn(b"Connection: close", resp)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[2:] if len(sys.argv) > 2 else [sys.argv[0]])
