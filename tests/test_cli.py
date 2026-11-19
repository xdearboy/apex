#!/usr/bin/env python3
"""Integration tests for the standalone `apex` CLI binary.

Run from the repository root after `make`:

    python3 tests/test_cli.py ./apex

Covers CLI flags, configuration validation, serving, SIGHUP hot reload,
SIGQUIT drain and orderly shutdown. Standard library only; the child server
is pinned to at most two CPUs when the platform allows it.
"""

import http.server
import json
import os
import shutil
import signal
import socket
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


def two_cpus():
    """Up to two CPUs allowed for this process, or None when unsupported."""
    try:
        allowed = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return None
    return allowed[:2] if allowed else None


def run_cli(args, timeout=15.0, env=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run([APEX, *args], capture_output=True, text=True, timeout=timeout, env=merged)


class Client:
    """Keep-alive HTTP client with strict Content-Length framing."""

    def __init__(self, port, host="127.0.0.1"):
        self.sock = socket.create_connection((host, port), timeout=REQUEST_TIMEOUT)

    def request(self, path="/", host_header="localhost", headers=None):
        status, _, body = self.request_full(path=path, host_header=host_header, headers=headers)
        return status, body

    def request_full(self, path="/", host_header="localhost", headers=None):
        lines = [f"GET {path} HTTP/1.1", f"Host: {host_header}", "Connection: keep-alive"]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        payload = "\r\n".join(lines) + "\r\n\r\n"
        self.sock.sendall(payload.encode())
        return self.read_response_full()

    def read_response(self):
        status, _, body = self.read_response_full()
        return status, body

    def read_response_full(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed before response headers")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        header_text = head.decode("latin-1")
        status = int(header_text.split("\r\n", 1)[0].split()[1])
        headers = {}
        for line in header_text.split("\r\n")[1:]:
            if not line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length", 0))
        while len(rest) < length:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed before response body")
            rest += chunk
        return status, headers, rest[:length]

    def closed_by_peer(self, probe_seconds=STOP_TIMEOUT):
        """Return True when the peer closes while this process stays alive."""
        self.sock.settimeout(0.25)
        deadline = time.time() + probe_seconds
        try:
            while time.time() < deadline:
                try:
                    if self.sock.recv(1) == b"":
                        return True
                except socket.timeout:
                    continue
        finally:
            self.sock.settimeout(REQUEST_TIMEOUT)
        return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class ApexServer:
    """Child `apex` process with log capture and deadline-based lifecycle."""

    def __init__(self, config_path, workdir, env=None):
        self.log_path = os.path.join(workdir, "apex.log")
        self.log_file = open(self.log_path, "ab")
        cpus = two_cpus()
        preexec = None
        if cpus and hasattr(os, "sched_setaffinity"):
            cpus = frozenset(cpus)

            def preexec():
                try:
                    os.sched_setaffinity(0, cpus)
                except OSError:
                    pass

        merged = dict(os.environ)
        if env:
            merged.update(env)
        self.proc = subprocess.Popen([APEX, "-c", config_path], stdout=self.log_file,
                                     stderr=self.log_file, preexec_fn=preexec, env=merged)

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
            self.close_log()
            raise AssertionError(f"apex ignored termination signal; log:\n{self.log_text()}")
        self.close_log()
        return self.proc.returncode

    def stop(self):
        """Idempotent teardown for tests that did not signal manually."""
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=STOP_TIMEOUT)
        self.close_log()
        return self.proc.returncode

    def log_text(self):
        try:
            with open(self.log_path, "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def close_log(self):
        if not self.log_file.closed:
            self.log_file.close()


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


SERVER_CONFIG = """http {{
    upstream edge {{
        server 127.0.0.1:{upstream_port};
        keepalive 8;
    }}
    server {{
        listen "127.0.0.1:{listen_port}";
        server_name {server_names};
        location "/" {{
            proxy_pass edge;
        }}
{extra_locations}
    }}
}}
"""

STATIC_LOCATION = """
        location "/static/" {{
            root "{static_dir}";
        }}
"""


def config_text(listen_port, upstream_port, server_names="localhost", static_dir=None):
    extra = STATIC_LOCATION.format(static_dir=static_dir) if static_dir else ""
    return SERVER_CONFIG.format(listen_port=listen_port, upstream_port=upstream_port,
                                server_names=server_names, extra_locations=extra)


def write_config(path, text):
    with open(path, "w") as handle:
        handle.write(text)
    return path


def replace_config(path, text):
    """Atomic rewrite so a SIGHUP never observes a half-written file."""
    temporary = f"{path}.tmp"
    with open(temporary, "w") as handle:
        handle.write(text)
    os.replace(temporary, path)


class CLIFlagTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-cli-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.workdir, name)

    def test_version_prints_metadata_without_reading_config(self):
        result = run_cli(["-v", "-c", self.path("missing.conf")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("apex/"), result.stdout)
        for marker in ("compiler:", "build flags:", "link flags:"):
            self.assertIn(marker, result.stdout)

    def test_check_accepts_valid_config(self):
        config = write_config(self.path("ok.conf"), config_text(free_port(), free_port()))
        result = run_cli(["-t", "-c", config])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid", result.stdout)

    def test_check_reports_syntax_error(self):
        config = self.path("broken.conf")
        write_config(config, "http {\n    upstream edge {\n        server 127.0.0.1:9001;\n")
        result = run_cli(["-t", "-c", config])
        self.assertEqual(result.returncode, 1)
        self.assertIn("broken.conf", result.stderr)

    def test_check_reports_semantic_error(self):
        config = self.path("semantic.conf")
        write_config(config, 'http {\n    server {\n        listen "127.0.0.1:18443";\n'
                             '        location "/" {\n            proxy_pass nosuch;\n        }\n    }\n}\n')
        result = run_cli(["-t", "-c", config])
        self.assertEqual(result.returncode, 1)
        self.assertIn("nosuch", result.stderr)

    def test_check_reports_missing_file(self):
        result = run_cli(["-t", "-c", self.path("absent.conf")])
        self.assertEqual(result.returncode, 1)
        self.assertIn("configuration", result.stderr)

    def test_check_does_not_start_listener(self):
        port = free_port()
        config = write_config(self.path("listener.conf"), config_text(port, free_port()))
        started = time.time()
        result = run_cli(["-t", "-c", config])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.time() - started, START_TIMEOUT)
        with self.assertRaises(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                self.fail("listener started despite -t")

    def test_rejects_invalid_cli_usage(self):
        for args in (["-x"], ["-c"], ["-c", ""], ["extra.conf"]):
            result = run_cli(args)
            self.assertEqual(result.returncode, 1, f"args={args}: {result.stderr}")
            self.assertIn("usage", result.stderr.lower())

    def test_default_config_path_is_used(self):
        if os.path.exists("/etc/apex/apex.conf"):
            self.skipTest("/etc/apex/apex.conf exists on this host")
        result = run_cli([])
        self.assertEqual(result.returncode, 1)
        self.assertIn("/etc/apex/apex.conf", result.stderr)


class ServingTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-serve-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.backend, self.backend_port = start_backend("backend-one")
        self.addCleanup(stop_backend, self.backend)
        self.static_dir = os.path.join(self.workdir, "static")
        os.mkdir(self.static_dir)
        with open(os.path.join(self.static_dir, "hello.txt"), "w") as handle:
            handle.write("static-body")
        self.listen_port = free_port()
        self.config = write_config(os.path.join(self.workdir, "apex.conf"),
                                   config_text(self.listen_port, self.backend_port,
                                               static_dir=self.static_dir))
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def test_proxy_request(self):
        status, body = Client(self.listen_port).request("/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"backend-one")

    def test_static_request(self):
        status, body = Client(self.listen_port).request("/static/hello.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"static-body")

    def test_unknown_host_uses_default_server(self):
        status, body = Client(self.listen_port).request("/", host_header="other.test")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"backend-one")

    def test_cli_ignores_port_environment(self):
        rogue_port = free_port()
        self.server.stop()  # free the configured port for the second instance
        env_server = ApexServer(self.config, self.workdir, env={"PORT": str(rogue_port)})
        try:
            env_server.wait_ready(self.listen_port)
            with self.assertRaises(OSError):
                with socket.create_connection(("127.0.0.1", rogue_port), timeout=0.5):
                    self.fail("PORT environment overrode the configuration listener")
        finally:
            env_server.stop()


class VhostTest(unittest.TestCase):
    def test_virtual_hosts_share_one_endpoint(self):
        workdir = tempfile.mkdtemp(prefix="apex-vhost-")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        alpha, alpha_port = start_backend("alpha-body")
        beta, beta_port = start_backend("beta-body")
        self.addCleanup(stop_backend, alpha)
        self.addCleanup(stop_backend, beta)
        listen_port = free_port()
        config = write_config(os.path.join(workdir, "apex.conf"),
                              f'http {{\n'
                              f'    upstream alpha {{ server 127.0.0.1:{alpha_port}; }}\n'
                              f'    upstream beta {{ server 127.0.0.1:{beta_port}; }}\n'
                              f'    server {{\n'
                              f'        listen "127.0.0.1:{listen_port}";\n'
                              f'        server_name a.test;\n'
                              f'        location "/" {{ proxy_pass alpha; }}\n'
                              f'    }}\n'
                              f'    server {{\n'
                              f'        listen "127.0.0.1:{listen_port}";\n'
                              f'        server_name b.test;\n'
                              f'        location "/" {{ proxy_pass beta; }}\n'
                              f'    }}\n'
                              f'}}\n')
        server = ApexServer(config, workdir)
        self.addCleanup(server.stop)
        server.wait_ready(listen_port)
        alpha_client = Client(listen_port)
        beta_client = Client(listen_port)
        try:
            self.assertEqual(alpha_client.request("/", host_header="a.test")[1], b"alpha-body")
            self.assertEqual(beta_client.request("/", host_header="b.test")[1], b"beta-body")
        finally:
            alpha_client.close()
            beta_client.close()


class BindConflictTest(unittest.TestCase):
    def test_bind_failure_exits_nonzero(self):
        workdir = tempfile.mkdtemp(prefix="apex-bind-")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        holder = socket.socket()
        self.addCleanup(holder.close)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.listen(1)
        config = write_config(os.path.join(workdir, "apex.conf"), config_text(port, free_port()))
        server = ApexServer(config, workdir)
        code = None
        try:
            code = server.wait_exit(timeout=START_TIMEOUT)
        except (subprocess.TimeoutExpired, AssertionError, TimeoutError):
            server.stop()
        self.assertIsNotNone(code, "apex stayed alive despite bind conflict")
        self.assertNotEqual(code, 0)
        self.assertIn("bind", server.log_text().lower())


class ReloadTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-reload-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.backend_old, self.old_port = start_backend("reload-old")
        self.backend_new, self.new_port = start_backend("reload-new")
        self.addCleanup(stop_backend, self.backend_old)
        self.addCleanup(stop_backend, self.backend_new)
        self.listen_port = free_port()
        self.config = os.path.join(self.workdir, "apex.conf")
        write_config(self.config, config_text(self.listen_port, self.old_port))
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def hup(self):
        self.server.proc.send_signal(1)  # SIGHUP

    def request_body(self, client, path="/", host_header="localhost"):
        return client.request(path, host_header=host_header)[1]

    def wait_body(self, client, expected, timeout=5.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            last = self.request_body(client)
            if last == expected.encode():
                return
            time.sleep(0.1)
        self.fail(f"never observed {expected!r}; last={last!r}")

    def test_successful_reload_updates_same_keepalive_socket(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        self.assertEqual(self.request_body(client), b"reload-old")
        replace_config(self.config, config_text(self.listen_port, self.new_port))
        self.hup()
        self.wait_body(client, "reload-new")
        self.assertTrue(self.server.alive())
        self.assertGreaterEqual(client.sock.fileno(), 0)  # same open socket throughout

    def test_rejected_reload_keeps_previous_configuration(self):
        replace_config(self.config, "http {\n    upstream edge {\n        server 127.0.0.1:9001;\n")
        self.hup()
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        self.wait_body(client, "reload-old")
        self.assertTrue(self.server.alive())
        self.assertIn("reload rejected", self.server.log_text())
        replace_config(self.config, config_text(self.listen_port, self.new_port))
        self.hup()
        self.wait_body(client, "reload-new")
        self.assertTrue(self.server.alive())

    def test_listener_change_reload_is_rejected(self):
        replace_config(self.config, config_text(self.listen_port + 1, self.new_port))
        self.hup()
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        self.wait_body(client, "reload-old")
        self.assertTrue(self.server.alive())
        self.assertIn("requires a restart", self.server.log_text())

    def test_unresolvable_upstream_reload_is_rejected(self):
        replace_config(self.config, config_text(self.listen_port, self.old_port)
                       .replace("127.0.0.1:", "nosuch-host.invalid:"))
        self.hup()
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        self.wait_body(client, "reload-old")
        self.assertTrue(self.server.alive())
        self.assertIn("reload rejected", self.server.log_text())

    def test_concurrent_requests_survive_repeated_reloads(self):
        failures = []
        rounds = 15

        def worker():
            try:
                client = Client(self.listen_port)
                for _ in range(rounds):
                    status, body = client.request("/")
                    if status != 200 or body not in (b"reload-old", b"reload-new"):
                        failures.append(f"status={status} body={body!r}")
                client.close()
            except OSError as error:  # pragma: no cover - diagnostics only
                failures.append(repr(error))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        time.sleep(0.1)
        replace_config(self.config, config_text(self.listen_port, self.new_port))
        self.hup()
        time.sleep(0.3)
        replace_config(self.config, config_text(self.listen_port, self.old_port))
        self.hup()
        for thread in threads:
            thread.join(timeout=REQUEST_TIMEOUT * rounds)
        self.assertEqual(failures, [])
        self.assertTrue(self.server.alive())

    def test_inflight_request_keeps_old_generation(self):
        slow, slow_port = start_backend("slow-old")
        self.addCleanup(stop_backend, slow)
        fast, fast_port = start_backend("fast-new")
        self.addCleanup(stop_backend, fast)
        replace_config(self.config, config_text(self.listen_port, slow_port))
        self.hup()
        probe = Client(self.listen_port)
        self.addCleanup(probe.close)
        self.wait_body(probe, "slow-old")

        result = {}

        def inflight():
            try:
                client = Client(self.listen_port)
                result["body"] = client.request("/delay/2.5")[1]
                client.close()
            except OSError as error:  # pragma: no cover - diagnostics only
                result["error"] = repr(error)

        thread = threading.Thread(target=inflight)
        thread.start()
        time.sleep(0.7)  # request is now blocked inside the slow backend
        replace_config(self.config, config_text(self.listen_port, fast_port))
        self.hup()  # reload while the slow request is still in flight
        thread.join(timeout=10.0)
        self.assertEqual(result.get("error"), None, result)
        self.assertEqual(result.get("body"), b"slow-old")
        self.wait_body(probe, "fast-new")


class SignalTest(unittest.TestCase):
    def start_with_slow_backend(self, body):
        self.workdir = tempfile.mkdtemp(prefix="apex-signal-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.backend, self.backend_port = start_backend(body)
        self.addCleanup(stop_backend, self.backend)
        self.listen_port = free_port()
        self.config = write_config(os.path.join(self.workdir, "apex.conf"),
                                   config_text(self.listen_port, self.backend_port))
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def test_sigquit_drains_inflight_and_closes_idle(self):
        self.start_with_slow_backend("drain-me")
        result = {}

        def inflight():
            try:
                client = Client(self.listen_port)
                result["body"] = client.request("/delay/2.5")[1]
                client.close()
            except OSError as error:  # pragma: no cover - diagnostics only
                result["error"] = repr(error)

        idle = Client(self.listen_port)
        thread = threading.Thread(target=inflight)
        thread.start()
        time.sleep(0.5)
        self.server.proc.send_signal(signal.SIGQUIT)
        thread.join(timeout=10.0)
        self.assertEqual(result.get("error"), None, result)
        self.assertEqual(result.get("body"), b"drain-me")
        self.assertTrue(idle.closed_by_peer(),
                        "idle connection stayed open during drain")
        self.assertEqual(self.server.wait_exit(timeout=STOP_TIMEOUT), 0)

    def test_sigquit_without_traffic_exits_zero(self):
        self.start_with_slow_backend("unused")
        self.server.proc.send_signal(signal.SIGQUIT)
        self.assertEqual(self.server.wait_exit(timeout=STOP_TIMEOUT), 0)

    def test_sigint_exits_zero(self):
        self.start_with_slow_backend("unused")
        self.server.proc.send_signal(signal.SIGINT)
        self.assertEqual(self.server.wait_exit(timeout=STOP_TIMEOUT), 0)

    def test_sigterm_exits_zero(self):
        self.start_with_slow_backend("unused")
        self.server.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.server.wait_exit(timeout=STOP_TIMEOUT), 0)


class ErrorPageTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-err-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.listen_port = free_port()
        self.dead_port = free_port()

    def test_default_404_razor_wing_html(self):
        config_text = f"""http {{
    upstream edge {{ server 127.0.0.1:{self.dead_port}; }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        location "/api/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/unmatched-path")
        self.assertEqual(status, 404)
        self.assertIn("text/html", headers.get("content-type", ""))
        text = body.decode("utf-8")
        self.assertIn("<title>apex — 404</title>", text)
        self.assertIn("not found", text)
        self.assertIn("this page could not be found.", text)
        self.assertIn("M4 8C14 8 26 14 28 26C20 22 14 18 10 14L4 8Z", text)

    def test_default_502_razor_wing_html_and_no_ip_leak(self):
        config_text = f"""http {{
    upstream edge {{ server 127.0.0.1:{self.dead_port}; }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/")
        self.assertEqual(status, 502)
        self.assertIn("text/html", headers.get("content-type", ""))
        text = body.decode("utf-8")
        self.assertIn("<title>apex — 502</title>", text)
        self.assertIn("bad gateway", text)
        self.assertIn("temporarily unreachable. try again in a moment.", text)
        self.assertIn("M4 8C14 8 26 14 28 26C20 22 14 18 10 14L4 8Z", text)
        # Verify strict anti-leak: never expose internal upstream IP or port
        self.assertNotIn(f":{self.dead_port}", text)
        self.assertNotIn("127.0.0.1", text)

    def test_json_error_negotiation(self):
        config_text = f"""http {{
    upstream edge {{ server 127.0.0.1:{self.dead_port}; }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/", headers={"Accept": "application/json"})
        self.assertEqual(status, 502)
        self.assertIn("application/json", headers.get("content-type", ""))
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["error"], 502)
        self.assertEqual(payload["status"], "bad gateway")
        self.assertEqual(payload["message"], "temporarily unreachable. try again in a moment.")

    def test_custom_error_page_served(self):
        custom_file = os.path.join(self.workdir, "custom_502.html")
        with open(custom_file, "w") as f:
            f.write("<!DOCTYPE html><html><body>custom brand error 502</body></html>")

        config_text = f"""http {{
    upstream edge {{ server 127.0.0.1:{self.dead_port}; }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        error_page 502 "{custom_file}";
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/")
        self.assertEqual(status, 502)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertEqual(body.decode("utf-8"), "<!DOCTYPE html><html><body>custom brand error 502</body></html>")

    def test_custom_error_page_fallback_when_file_missing(self):
        missing_file = os.path.join(self.workdir, "nonexistent.html")
        config_text = f"""http {{
    upstream edge {{ server 127.0.0.1:{self.dead_port}; }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        error_page 502 "{missing_file}";
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/")
        self.assertEqual(status, 502)
        self.assertIn("text/html", headers.get("content-type", ""))
        text = body.decode("utf-8")
        self.assertIn("<title>apex — 502</title>", text)
        self.assertIn("bad gateway", text)


class UpstreamFailoverTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-failover-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.backend, self.backend_port = start_backend("healthy-backend-payload")
        self.addCleanup(stop_backend, self.backend)
        self.dead_port = free_port()
        self.listen_port = free_port()

    def test_next_upstream_failover_serves_200(self):
        config_text = f"""http {{
    upstream edge {{
        server 127.0.0.1:{self.dead_port};
        server 127.0.0.1:{self.backend_port};
        connect_timeout 500ms;
        max_fails 2;
        fail_timeout 5s;
        max_retries 2;
    }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, body = client.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"healthy-backend-payload")

        # Second request: dead server should remain avoided, traffic flows smoothly
        status2, body2 = client.request("/")
        self.assertEqual(status2, 200)
        self.assertEqual(body2, b"healthy-backend-payload")

    def test_health_check_directive_and_active_prober(self):
        config_text = f"""http {{
    upstream edge {{
        server 127.0.0.1:{self.backend_port};
        health_check uri=/ interval=1s timeout=500ms fall=2 rise=2;
        max_fails 3;
        fail_timeout 5s;
        max_retries 2;
    }}
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;
        location "/" {{
            proxy_pass edge;
        }}
    }}
}}
"""
        config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        check = run_cli(["-t", "-c", config])
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("valid", check.stdout)

        server = ApexServer(config, self.workdir)
        self.addCleanup(server.stop)
        server.wait_ready(self.listen_port)

        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, body = client.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"healthy-backend-payload")


class ModulePipelineTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-mod-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.listen_port = free_port()
        self.backend, self.backend_port = start_backend("mod-backend")
        self.addCleanup(stop_backend, self.backend)

        # Locate mod_security_headers.so
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        so_path = os.path.join(repo_root, "examples", "mod_security_headers.so")
        self.assertTrue(os.path.exists(so_path), f"Module not found at {so_path}")

        config_text = f"""modules {{
    load "{so_path}";
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
        self.config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def test_module_response_filter_injects_headers(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, headers, body = client.request_full("/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"mod-backend")
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("x-apex-module"), "mod_security_headers")

    def test_module_access_control_denies_request(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)
        status, body = client.request("/mod-forbidden")
        self.assertEqual(status, 403)


class StaticServerEngineTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="apex-static-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.listen_port = free_port()

        self.static_root = os.path.join(self.workdir, "www")
        os.makedirs(self.static_root, exist_ok=True)

        with open(os.path.join(self.static_root, "index.html"), "w") as f:
            f.write("<html>apex web server</html>")
        with open(os.path.join(self.static_root, "style.css"), "w") as f:
            f.write("body { margin: 0; }")
        with open(os.path.join(self.static_root, "script.js"), "w") as f:
            f.write("console.log('apex');")
        with open(os.path.join(self.static_root, "data.json"), "w") as f:
            f.write('{"server":"apex"}')
        with open(os.path.join(self.static_root, "module.wasm"), "wb") as f:
            f.write(b"\x00asm\x01\x00\x00\x00")
        with open(os.path.join(self.static_root, "logo.svg"), "w") as f:
            f.write('<svg viewBox="0 0 10 10"></svg>')

        # Precompressed twins
        with open(os.path.join(self.static_root, "bundle.js"), "w") as f:
            f.write("uncompressed bundle code")
        with open(os.path.join(self.static_root, "bundle.js.gz"), "w") as f:
            f.write("gzip-twin-content")
        with open(os.path.join(self.static_root, "bundle.js.br"), "w") as f:
            f.write("brotli-twin-content")

        # Subdirectory for index test
        sub_dir = os.path.join(self.static_root, "sub")
        os.makedirs(sub_dir, exist_ok=True)
        with open(os.path.join(sub_dir, "custom.html"), "w") as f:
            f.write("custom index page")

        config_text = f"""http {{
    server {{
        listen "127.0.0.1:{self.listen_port}";
        server_name localhost;

        location "/static/" {{
            root "{self.static_root}";
            sendfile on;
            etag on;
            precompressed on;
        }}

        location "/sub/" {{
            root "{sub_dir}";
            index custom.html;
        }}

        location "/app/" {{
            root "{self.static_root}";
            try_files $uri $uri/ /index.html;
        }}
    }}
}}
"""
        self.config = write_config(os.path.join(self.workdir, "apex.conf"), config_text)
        self.server = ApexServer(self.config, self.workdir)
        self.addCleanup(self.server.stop)
        self.server.wait_ready(self.listen_port)

    def test_static_mime_types(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        cases = [
            ("/static/index.html", "text/html; charset=utf-8"),
            ("/static/style.css", "text/css; charset=utf-8"),
            ("/static/script.js", "application/javascript; charset=utf-8"),
            ("/static/data.json", "application/json"),
            ("/static/module.wasm", "application/wasm"),
            ("/static/logo.svg", "image/svg+xml"),
        ]
        for path, expected_mime in cases:
            status, headers, _ = client.request_full(path)
            self.assertEqual(status, 200, f"Failed for {path}")
            self.assertEqual(headers.get("content-type"), expected_mime, f"MIME mismatch for {path}")

    def test_etag_and_304_not_modified(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        status, headers, body = client.request_full("/static/index.html")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"<html>apex web server</html>")
        etag = headers.get("etag")
        self.assertTrue(etag, "ETag missing from static response")

        # Second request with If-None-Match
        status2, headers2, body2 = client.request_full("/static/index.html", headers={"If-None-Match": etag})
        self.assertEqual(status2, 304)
        self.assertEqual(len(body2), 0)

    def test_last_modified_and_304(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        status, headers, _ = client.request_full("/static/style.css")
        self.assertEqual(status, 200)
        last_mod = headers.get("last-modified")
        self.assertTrue(last_mod, "Last-Modified header missing")

        # Request with If-Modified-Since
        status2, _, body2 = client.request_full("/static/style.css", headers={"If-Modified-Since": last_mod})
        self.assertEqual(status2, 304)
        self.assertEqual(len(body2), 0)

    def test_precompressed_twins_selection(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        # Brotli preferred
        status, headers, body = client.request_full("/static/bundle.js", headers={"Accept-Encoding": "gzip, br"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("content-encoding"), "br")
        self.assertEqual(body, b"brotli-twin-content")
        self.assertIn("Accept-Encoding", headers.get("vary", ""))

        # Gzip fallback
        status_gz, headers_gz, body_gz = client.request_full("/static/bundle.js", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(status_gz, 200)
        self.assertEqual(headers_gz.get("content-encoding"), "gzip")
        self.assertEqual(body_gz, b"gzip-twin-content")

        # No compression accepted -> uncompressed original
        status_raw, headers_raw, body_raw = client.request_full("/static/bundle.js", headers={"Accept-Encoding": "identity"})
        self.assertEqual(status_raw, 200)
        self.assertIsNone(headers_raw.get("content-encoding"))
        self.assertEqual(body_raw, b"uncompressed bundle code")

    def test_http_range_requests(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        # "console.log('apex');" length is 20 bytes. Request bytes 0-6 ("console")
        status, headers, body = client.request_full("/static/script.js", headers={"Range": "bytes=0-6"})
        self.assertEqual(status, 206)
        self.assertEqual(body, b"console")
        self.assertEqual(headers.get("content-length"), "7")
        self.assertIn("bytes 0-6/20", headers.get("content-range", ""))

    def test_custom_index_directive(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        status, body = client.request("/sub/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"custom index page")

    def test_try_files_fallback(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        # Existing file -> served directly
        status1, body1 = client.request("/app/style.css")
        self.assertEqual(status1, 200)
        self.assertEqual(body1, b"body { margin: 0; }")

        # Missing file -> falls back to /index.html
        status2, body2 = client.request("/app/some/client/side/route")
        self.assertEqual(status2, 200)
        self.assertEqual(body2, b"<html>apex web server</html>")

    def test_directory_traversal_protection(self):
        client = Client(self.listen_port)
        self.addCleanup(client.close)

        status1, _ = client.request("/static/../etc/passwd")
        self.assertIn(status1, (403, 404))

        status2, _ = client.request("/static/%2e%2e/passwd")
        self.assertIn(status2, (403, 404))


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()


