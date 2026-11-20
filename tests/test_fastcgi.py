#!/usr/bin/env python3
"""Integration tests for FastCGI / PHP-FPM Gateway (fastcgi_pass) in Apex.

Covers:
- FastCGI protocol over TCP socket
- FastCGI protocol over Unix domain socket (AF_UNIX)
- CGI environment parameters: SCRIPT_FILENAME, REQUEST_METHOD, QUERY_STRING, HTTP_* headers
- Request body streaming over FCGI_STDIN
- Response parsing from FCGI_STDOUT with custom Status codes and headers
"""

import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0

FCGI_VERSION_1 = 1
FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7

FCGI_RESPONDER = 1
FCGI_REQUEST_COMPLETE = 0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def decode_length(data, pos):
    b0 = data[pos]
    if b0 < 128:
        return b0, pos + 1
    b1, b2, b3 = data[pos + 1], data[pos + 2], data[pos + 3]
    length = ((b0 & 0x7F) << 24) | (b1 << 16) | (b2 << 8) | b3
    return length, pos + 4


def parse_fcgi_params(data):
    params = {}
    pos = 0
    while pos < len(data):
        nlen, pos = decode_length(data, pos)
        vlen, pos = decode_length(data, pos)
        name = data[pos : pos + nlen].decode("utf-8", errors="replace")
        pos += nlen
        val = data[pos : pos + vlen].decode("utf-8", errors="replace")
        pos += vlen
        params[name] = val
    return params


def send_fcgi_record(sock, req_id, rec_type, content=b""):
    clen = len(content)
    hdr = struct.pack(">BBHHBB", FCGI_VERSION_1, rec_type, req_id, clen, 0, 0)
    sock.sendall(hdr + content)


class MockFastCGIServer:
    def __init__(self, is_unix=False, path=None):
        self.is_unix = is_unix
        self.path = path
        self.running = True
        self.last_params = {}
        self.last_body = b""
        self.server_sock = None
        self.port = None

        if self.is_unix:
            if os.path.exists(path):
                os.unlink(path)
            self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server_sock.bind(path)
        else:
            self.port = free_port()
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("127.0.0.1", self.port))

        self.server_sock.listen(16)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
            except OSError:
                break
            try:
                self.handle_client(conn)
            except Exception:
                pass
            finally:
                conn.close()

    def handle_client(self, sock):
        req_id = 1
        raw_params = bytearray()
        body = bytearray()

        while True:
            hdr_bytes = recv_exact(sock, 8)
            if not hdr_bytes:
                break
            version, rec_type, rid, clen, plen, _ = struct.unpack(">BBHHBB", hdr_bytes)
            content = recv_exact(sock, clen) if clen > 0 else b""
            if plen > 0:
                recv_exact(sock, plen)

            req_id = rid

            if rec_type == FCGI_PARAMS:
                if clen == 0:
                    pass  # Params done
                else:
                    raw_params.extend(content)
            elif rec_type == FCGI_STDIN:
                if clen == 0:
                    break  # Stdin done
                else:
                    body.extend(content)

        self.last_params = parse_fcgi_params(bytes(raw_params))
        self.last_body = bytes(body)

        # Decide response
        script_name = self.last_params.get("SCRIPT_NAME", "")
        if "notfound" in script_name:
            resp_body = b"Custom 404 From FastCGI"
            resp_hdr = (
                b"Status: 404 Not Found\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n"
            )
        else:
            payload = json.dumps({
                "method": self.last_params.get("REQUEST_METHOD", ""),
                "uri": self.last_params.get("REQUEST_URI", ""),
                "query": self.last_params.get("QUERY_STRING", ""),
                "script_filename": self.last_params.get("SCRIPT_FILENAME", ""),
                "user_agent": self.last_params.get("HTTP_USER_AGENT", ""),
                "body_len": len(self.last_body),
                "body": self.last_body.decode("utf-8", errors="replace"),
            }).encode("utf-8")
            resp_hdr = (
                b"Status: 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"X-Powered-By: Apex-FastCGI\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
            )
            resp_body = payload

        # Send FCGI_STDOUT
        send_fcgi_record(sock, req_id, FCGI_STDOUT, resp_hdr + resp_body)
        send_fcgi_record(sock, req_id, FCGI_STDOUT, b"")

        # Send FCGI_END_REQUEST
        end_body = struct.pack(">IB3s", 0, FCGI_REQUEST_COMPLETE, b"\x00\x00\x00")
        send_fcgi_record(sock, req_id, FCGI_END_REQUEST, end_body)

    def close(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()
        if self.is_unix and os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass


class TestFastCGI(unittest.TestCase):
    def setUp(self):
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

    def test_01_fastcgi_tcp_get(self):
        fcgi_server = MockFastCGIServer(is_unix=False)
        try:
            conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;
        root /var/www/html;

        location /app/ {{
            fastcgi_pass 127.0.0.1:{fcgi_server.port};
            fastcgi_index index.php;
        }}
    }}
}}
"""
            self.start_apex(conf)

            conn = http.client.HTTPConnection("127.0.0.1", self.port)
            conn.request("GET", "/app/users?sort=desc", headers={"User-Agent": "ApexFastCGITest/1.0"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("X-Powered-By"), "Apex-FastCGI")
            data = json.loads(resp.read().decode("utf-8"))
            conn.close()

            self.assertEqual(data["method"], "GET")
            self.assertEqual(data["uri"], "/app/users")
            self.assertEqual(data["query"], "sort=desc")
            self.assertEqual(data["user_agent"], "ApexFastCGITest/1.0")
            self.assertEqual(data["script_filename"], "/var/www/html/app/users")
        finally:
            fcgi_server.close()

    def test_02_fastcgi_post_stdin(self):
        fcgi_server = MockFastCGIServer(is_unix=False)
        try:
            conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;
        root /var/www/app;

        location /api/ {{
            fastcgi_pass 127.0.0.1:{fcgi_server.port};
        }}
    }}
}}
"""
            self.start_apex(conf)

            post_body = json.dumps({"action": "create_user", "username": "admin"})
            conn = http.client.HTTPConnection("127.0.0.1", self.port)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Poster/2.0",
            }
            conn.request("POST", "/api/v1/users", body=post_body, headers=headers)
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            conn.close()

            self.assertEqual(data["method"], "POST")
            self.assertEqual(data["body"], post_body)
            self.assertEqual(data["body_len"], len(post_body))
        finally:
            fcgi_server.close()

    def test_03_fastcgi_unix_socket(self):
        sock_path = os.path.join(self.temp_dir.name, "php-fpm.sock")
        fcgi_server = MockFastCGIServer(is_unix=True, path=sock_path)
        try:
            conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;
        root /srv/http;

        location / {{
            fastcgi_pass unix:{sock_path};
            fastcgi_index index.php;
        }}
    }}
}}
"""
            self.start_apex(conf)

            conn = http.client.HTTPConnection("127.0.0.1", self.port)
            conn.request("GET", "/index.php")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            conn.close()

            self.assertEqual(data["uri"], "/index.php")
            self.assertEqual(data["script_filename"], "/srv/http/index.php")
        finally:
            fcgi_server.close()

    def test_04_fastcgi_custom_status_code(self):
        fcgi_server = MockFastCGIServer(is_unix=False)
        try:
            conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port};
        server_name localhost;

        location / {{
            fastcgi_pass 127.0.0.1:{fcgi_server.port};
        }}
    }}
}}
"""
            self.start_apex(conf)

            conn = http.client.HTTPConnection("127.0.0.1", self.port)
            conn.request("GET", "/notfound")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 404)
            body = resp.read()
            self.assertEqual(body, b"Custom 404 From FastCGI")
            conn.close()
        finally:
            fcgi_server.close()


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
