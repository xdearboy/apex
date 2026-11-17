#!/usr/bin/env python3
"""Integration tests for the TLS transport of the standalone `apex` binary.

Run from the repository root after `make`:

    python3 tests/test_tls.py ./apex

Covers TLS listeners, ALPN negotiation (http/1.1 only until HTTP/2 support
lands), configuration validation of certificate material, reload rejection
and orderly shutdown. Standard library only; requires the `openssl` CLI to
generate throwaway certificate/key pairs.
"""

import os
import shutil
import signal
import socket
import ssl
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
    """Self-signed pair; returns (certificate_path, key_path)."""
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
        spec = self.server.apex_test_spec
        if self.path.startswith("/delay/"):
            time.sleep(float(self.path.rsplit("/", 1)[1]))
        body = spec["body"].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_backend(body):
    port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _BackendHandler)
    server.apex_test_spec = {"body": body}
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


class TlsClient:
    """Minimal keep-alive TLS client speaking the server's h1 dialect."""

    def __init__(self, port, alpn, context=None):
        if context is None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(alpn)
        self.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=REQUEST_TIMEOUT))

    def alpn(self):
        return self.sock.selected_alpn_protocol()

    def request(self, path="/", host_header="localhost"):
        request_line = f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: keep-alive\r\n\r\n"
        self.sock.sendall(request_line.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed before response headers")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        status = int(head.decode("latin-1").split("\r\n", 1)[0].split()[1])
        length = 0
        for line in head.decode("latin-1").split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length":
                length = int(value.strip())
        while len(rest) < length:
            rest += self.sock.recv(4096)
        return status, rest[:length]

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
                        return False  # RST-like teardown, not an orderly close
                    raise
        finally:
            self.sock.settimeout(REQUEST_TIMEOUT)
        return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def run_cli(args, timeout=15.0):
    return subprocess.run([APEX, *args], capture_output=True, text=True, timeout=timeout)


class TlsServingTest(unittest.TestCase):
    """Server lifecycle shared by serving and signal cases."""

    def setUp(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl CLI not available")
        self.workdir = tempfile.mkdtemp(prefix="apex-tls-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.cert, self.key = make_certificate(self.workdir, "server")
        self.backend, self.backend_port = start_backend("tls-backend")
        self.addCleanup(stop_backend, self.backend)
        self.listen_port = free_port()
        self.config = os.path.join(self.workdir, "apex.conf")
        self.write_config()
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def write_config(self, certificate=None, key=None):
        text = TLS_CONFIG.format(listen_port=self.listen_port, upstream_port=self.backend_port,
                                 certificate=certificate or self.cert, key=key or self.key)
        temporary = f"{self.config}.tmp"
        with open(temporary, "w") as handle:
            handle.write(text)
        os.replace(temporary, self.config)

    def test_alpn_http11_serving_and_keepalive(self):
        client = TlsClient(self.listen_port, ["http/1.1"])
        self.addCleanup(client.close)
        self.assertEqual(client.alpn(), "http/1.1")
        for _ in range(3):  # same TLS connection, pipelined h1 semantics
            status, body = client.request("/")
            self.assertEqual((status, body), (200, b"tls-backend"))

    def test_alpn_prefers_http11_until_h2_lands(self):
        client = TlsClient(self.listen_port, ["h2", "http/1.1"])
        self.addCleanup(client.close)
        self.assertEqual(client.alpn(), "http/1.1")
        self.assertEqual(client.request("/")[0], 200)

    def test_alpn_no_overlap_fails_handshake(self):
        with self.assertRaises(ssl.SSLError):
            TlsClient(self.listen_port, ["bogus/1"])
        self.assertTrue(self.server.alive())
        # The server must keep serving new clients afterwards.
        healthy = TlsClient(self.listen_port, ["http/1.1"])
        self.addCleanup(healthy.close)
        self.assertEqual(healthy.request("/")[0], 200)

    def test_plaintext_to_tls_port_rejected(self):
        with socket.create_connection(("127.0.0.1", self.listen_port), timeout=REQUEST_TIMEOUT) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                raw.settimeout(2.0)
                while raw.recv(4096):
                    pass
        self.assertTrue(self.server.alive())

    def test_sigterm_exits_zero(self):
        self.server.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait_exit(), 0)

    def test_idle_tls_connection_closes_with_eof_on_sigquit(self):
        idle = TlsClient(self.listen_port, ["http/1.1"])
        self.addCleanup(idle.close)
        self.server.proc.send_signal(signal.SIGQUIT)
        self.assertTrue(idle.wait_for_eof(), "idle TLS connection was not closed orderly")
        self.assertEqual(self.server.wait_exit(), 0)

    def test_sigquit_drains_inflight_tls_request(self):
        slow, slow_port = start_backend("slow-drain")
        self.addCleanup(stop_backend, slow)
        self.write_config_with_upstream(slow_port)
        self.server.proc.send_signal(signal.SIGHUP)
        probe = TlsClient(self.listen_port, ["http/1.1"])
        self.addCleanup(probe.close)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                if probe.request("/")[1] == b"slow-drain":
                    break
            except (ConnectionError, ssl.SSLError, OSError):
                pass
            time.sleep(0.1)
        else:
            self.fail("reload to slow backend never took effect")

        result = {}

        def inflight():
            try:
                client = TlsClient(self.listen_port, ["http/1.1"])
                result["body"] = client.request("/delay/2.5")[1]
                client.close()
            except (OSError, ssl.SSLError) as error:
                result["error"] = repr(error)

        thread = threading.Thread(target=inflight)
        thread.start()
        time.sleep(0.5)
        self.server.proc.send_signal(signal.SIGQUIT)
        thread.join(timeout=STOP_TIMEOUT)
        self.assertEqual(result.get("error"), None, result)
        self.assertEqual(result.get("body"), b"slow-drain")
        self.assertEqual(self.server.wait_exit(), 0)

    def write_config_with_upstream(self, upstream_port):
        text = TLS_CONFIG.format(listen_port=self.listen_port, upstream_port=upstream_port,
                                 certificate=self.cert, key=self.key)
        temporary = f"{self.config}.tmp"
        with open(temporary, "w") as handle:
            handle.write(text)
        os.replace(temporary, self.config)

    def test_reload_cert_change_rejected(self):
        other_cert, other_key = make_certificate(self.workdir, "other")
        client = TlsClient(self.listen_port, ["http/1.1"])
        self.addCleanup(client.close)
        self.assertEqual(client.request("/")[1], b"tls-backend")
        self.write_config(certificate=other_cert, key=other_key)
        self.server.proc.send_signal(signal.SIGHUP)
        self.wait_for_reload_rejection()
        self.assertTrue(self.server.alive())
        self.assertEqual(client.request("/")[1], b"tls-backend")  # same keepalive socket
        self.assertIn("requires a restart", self.server.log_text())

    def wait_for_reload_rejection(self, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "requires a restart" in self.server.log_text():
                return
            time.sleep(0.05)
        self.fail("reload was not rejected; log:\n" + self.server.log_text())


class TlsConfigTest(unittest.TestCase):
    def setUp(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl CLI not available")
        self.workdir = tempfile.mkdtemp(prefix="apex-tls-conf-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.cert, self.key = make_certificate(self.workdir, "server")
        self.bad_cert, self.bad_key = make_certificate(self.workdir, "bad")

    def path(self, name):
        return os.path.join(self.workdir, name)

    def check(self, config, expect_zero):
        result = run_cli(["-t", "-c", config])
        self.assertEqual(result.returncode, 0 if expect_zero else 1, f"{result.stdout}{result.stderr}")

    def test_valid_tls_config(self):
        config = self.path("ok.conf")
        with open(config, "w") as handle:
            handle.write(TLS_CONFIG.format(listen_port=free_port(), upstream_port=free_port(),
                                           certificate=self.cert, key=self.key))
        self.check(config, True)

    def test_listen_tls_without_tls_block(self):
        config = self.path("no-tls-block.conf")
        with open(config, "w") as handle:
            handle.write('http {\n    server {\n        listen "127.0.0.1:18443" tls;\n'
                         '        server_name localhost;\n        location "/" { proxy_pass edge; }\n'
                         '    }\n    upstream edge { server 127.0.0.1:19001; }\n}\n')
        self.check(config, False)

    def test_key_mismatch_rejected(self):
        config = self.path("mismatch.conf")
        with open(config, "w") as handle:
            handle.write(TLS_CONFIG.format(listen_port=free_port(), upstream_port=free_port(),
                                           certificate=self.cert, key=self.bad_key))
        self.check(config, False)

    def test_missing_certificate_file(self):
        config = self.path("missing.conf")
        with open(config, "w") as handle:
            handle.write(TLS_CONFIG.format(listen_port=free_port(), upstream_port=free_port(),
                                           certificate=self.path("absent.pem"), key=self.key))
        self.check(config, False)

    def test_plain_config_still_valid(self):
        config = self.path("plain.conf")
        with open(config, "w") as handle:
            handle.write('http {\n    upstream edge { server 127.0.0.1:19001; }\n'
                         '    server {\n        listen "127.0.0.1:18443";\n        server_name localhost;\n'
                         '        location "/" { proxy_pass edge; }\n    }\n}\n')
        self.check(config, True)


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
