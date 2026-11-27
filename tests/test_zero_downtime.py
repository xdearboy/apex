#!/usr/bin/env python3
"""Integration tests for Apex zero-downtime binary upgrade (SIGUSR2)."""

import http.server
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = sys.argv[1] if len(sys.argv) > 1 else "./apex"


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from upstream backend\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestZeroDowntimeUpgrade(unittest.TestCase):
    def setUp(self):
        self.backend_port = find_free_port()
        self.listen_port = find_free_port()
        self.workdir = tempfile.mkdtemp(prefix="apex-upgrade-test-")

        # Start backend HTTP server
        self.backend = http.server.HTTPServer(("127.0.0.1", self.backend_port), BackendHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()

        # Write apex configuration
        self.config_path = os.path.join(self.workdir, "apex.conf")
        config_content = f"""
http {{
    server {{
        listen 127.0.0.1:{self.listen_port};

        location / {{
            proxy_pass http://127.0.0.1:{self.backend_port};
        }}
    }}
}}
"""
        with open(self.config_path, "w") as f:
            f.write(config_content)

        self.log_path = os.path.join(self.workdir, "apex.log")
        self.log_file = open(self.log_path, "ab")
        self.child_pid = None

    def tearDown(self):
        if hasattr(self, "backend"):
            self.backend.shutdown()
            self.backend.server_close()
        if hasattr(self, "log_file") and not self.log_file.closed:
            self.log_file.close()
        if getattr(self, "child_pid", None) is not None:
            try:
                os.kill(self.child_pid, signal.SIGKILL)
            except OSError:
                pass

    def test_zero_downtime_sigusr2_upgrade(self):
        # 1. Start initial master process
        proc1 = subprocess.Popen(
            [APEX, "-c", self.config_path],
            stdout=self.log_file,
            stderr=self.log_file,
        )

        try:
            # Wait until initial master is serving
            ready = False
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", self.listen_port), timeout=0.1) as s:
                        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                        resp = s.recv(4096)
                        if b"200 OK" in resp:
                            ready = True
                            break
                except OSError:
                    time.sleep(0.05)
            self.assertTrue(ready, "Initial Apex master failed to start")

            # 2. Launch concurrent traffic in background
            stop_traffic = threading.Event()
            success_count = 0
            failure_count = 0
            traffic_lock = threading.Lock()

            def traffic_worker():
                nonlocal success_count, failure_count
                while not stop_traffic.is_set():
                    req_success = False
                    for attempt in range(3):
                        try:
                            with socket.create_connection(("127.0.0.1", self.listen_port), timeout=1.0) as s:
                                s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                                data = b""
                                while True:
                                    chunk = s.recv(4096)
                                    if not chunk:
                                        break
                                    data += chunk
                                if b"200 OK" in data and b"hello from upstream backend" in data:
                                    req_success = True
                                    break
                        except (ConnectionRefusedError, ConnectionResetError, OSError):
                            if stop_traffic.is_set():
                                break
                            time.sleep(0.01)
                            continue
                        except Exception:
                            break
                    with traffic_lock:
                        if req_success:
                            success_count += 1
                        else:
                            if not stop_traffic.is_set():
                                failure_count += 1
                    time.sleep(0.01)

            threads = [threading.Thread(target=traffic_worker) for _ in range(4)]
            for t in threads:
                t.start()

            # Let some traffic flow
            time.sleep(0.2)

            # 3. Send SIGUSR2 to initial master to trigger binary upgrade
            proc1.send_signal(signal.SIGUSR2)

            # 4. Wait for child PID to be reported in the log
            child_pid = None
            for _ in range(50):
                with open(self.log_path, "r", errors="replace") as f:
                    log_text = f.read()
                m = re.search(r"spawned upgraded binary with PID (\d+)", log_text)
                if m:
                    child_pid = int(m.group(1))
                    break
                time.sleep(0.1)

            self.assertIsNotNone(child_pid, f"Child PID not found in log:\n{log_text}")
            self.child_pid = child_pid

            # Verify child process is alive
            time.sleep(0.5)
            self.assertTrue(os.path.exists(f"/proc/{child_pid}"), f"Child process {child_pid} is not alive")

            # 5. Send SIGQUIT to old master to drain gracefully
            proc1.send_signal(signal.SIGQUIT)
            proc1_exit = proc1.wait(timeout=10)
            self.assertEqual(proc1_exit, 0, "Old master process did not exit with code 0 on SIGQUIT")

            # 6. Ensure child process is still alive and serving traffic
            self.assertTrue(os.path.exists(f"/proc/{child_pid}"), f"New master {child_pid} exited prematurely")

            # Let traffic continue to hit new master
            time.sleep(0.5)

            # Stop traffic
            stop_traffic.set()
            for t in threads:
                t.join(timeout=2.0)

            # Verify 0 failures occurred during the upgrade
            with traffic_lock:
                self.assertGreater(success_count, 20, "Expected at least 20 successful requests")
                self.assertEqual(failure_count, 0, f"Observed {failure_count} failed requests during binary upgrade")

            # 7. Cleanly terminate new master
            os.kill(child_pid, signal.SIGQUIT)
            for _ in range(50):
                if not os.path.exists(f"/proc/{child_pid}"):
                    break
                time.sleep(0.1)
            if os.path.exists(f"/proc/{child_pid}"):
                os.kill(child_pid, signal.SIGKILL)
            self.child_pid = None

        finally:
            if proc1.poll() is None:
                proc1.kill()
                proc1.wait()
            if self.child_pid is not None:
                try:
                    os.kill(self.child_pid, signal.SIGKILL)
                except OSError:
                    pass
                self.child_pid = None


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[2:])
