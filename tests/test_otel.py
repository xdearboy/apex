#!/usr/bin/env python3
"""Integration tests for OpenTelemetry / W3C Trace Context in Apex.

Covers:
- Generation of W3C traceparent (00-{trace_id}-{span_id}-{flags})
- Propagation of incoming traceparent with new child span_id
- Propagation of tracestate header
- $otel_trace_id, $otel_span_id, and $otel_parent_id variable expansion
- otel off disables tracing
"""

import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

APEX = os.path.abspath("./apex")
for arg in sys.argv[1:]:
    if not arg.startswith("-") and os.path.isfile(arg):
        APEX = os.path.abspath(arg)
        break

START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class OtelBackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"otel-backend-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        # Echo back received trace headers for verification
        tp = self.headers.get("traceparent", "")
        ts = self.headers.get("tracestate", "")
        if tp:
            self.send_header("X-Echo-Traceparent", tp)
        if ts:
            self.send_header("X-Echo-Tracestate", ts)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestOpenTelemetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_port = free_port()
        cls.apex_port = free_port()

        cls.httpd = http.server.HTTPServer(("127.0.0.1", cls.backend_port), OtelBackendHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

        cls.conf_file = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        cls.conf_file.write(f"""
http {{
    worker_connections 256;

    upstream otel_pool {{
        server 127.0.0.1:{cls.backend_port};
    }}

    server {{
        listen {cls.apex_port};

        location /otel/ {{
            otel on;
            otel_trace_context propagate;
            add_header X-Trace-Id $otel_trace_id always;
            add_header X-Span-Id $otel_span_id always;
            add_header X-Parent-Id $otel_parent_id always;
            proxy_pass http://otel_pool;
        }}

        location /no_otel/ {{
            otel off;
            add_header X-Trace-Id $otel_trace_id always;
            proxy_pass http://otel_pool;
        }}
    }}
}}
""")
        cls.conf_file.flush()
        cls.conf_file.close()

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_file.name])
        deadline = time.time() + START_TIMEOUT
        started = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.apex_port), timeout=0.2):
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
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.httpd.shutdown()
        os.unlink(cls.conf_file.name)

    def _request(self, path, extra_headers=None):
        with socket.create_connection(("127.0.0.1", self.apex_port), timeout=3.0) as sock:
            hdrs = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            if extra_headers:
                for k, v in extra_headers.items():
                    hdrs += f"{k}: {v}\r\n"
            hdrs += "\r\n"
            sock.sendall(hdrs.encode("utf-8"))
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            header_part, _, body = resp.partition(b"\r\n\r\n")
            lines = header_part.decode("utf-8", errors="replace").split("\r\n")
            status_line = lines[0]
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v
            return status_line, headers, body

    def test_01_otel_new_trace_generation(self):
        """Test generation of new W3C traceparent and variable expansion."""
        status_line, headers, body = self._request("/otel/test")
        self.assertIn("200 OK", status_line)
        self.assertEqual(body, b"otel-backend-ok")

        # Response headers should contain expanded variables
        self.assertIn("X-Trace-Id", headers)
        self.assertIn("X-Span-Id", headers)
        trace_id = headers["X-Trace-Id"]
        span_id = headers["X-Span-Id"]

        # Validate hex format (32 hex for trace_id, 16 hex for span_id)
        self.assertTrue(re.match(r"^[0-9a-f]{32}$", trace_id), f"Invalid trace_id: {trace_id}")
        self.assertTrue(re.match(r"^[0-9a-f]{16}$", span_id), f"Invalid span_id: {span_id}")

        # Upstream backend should have received the injected traceparent
        self.assertIn("X-Echo-Traceparent", headers)
        echoed_tp = headers["X-Echo-Traceparent"]
        self.assertEqual(echoed_tp, f"00-{trace_id}-{span_id}-01")

    def test_02_otel_trace_propagation(self):
        """Test propagation of client traceparent and tracestate."""
        client_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        client_parent_id = "00f067aa0ba902b7"
        client_tp = f"00-{client_trace_id}-{client_parent_id}-01"
        client_ts = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"

        status_line, headers, _ = self._request("/otel/propagate", extra_headers={
            "traceparent": client_tp,
            "tracestate": client_ts
        })
        self.assertIn("200 OK", status_line)

        # Trace ID must be preserved
        self.assertEqual(headers.get("X-Trace-Id"), client_trace_id)
        # Parent ID must equal the client's span ID
        self.assertEqual(headers.get("X-Parent-Id"), client_parent_id)

        # Backend must receive the propagated traceparent with new span_id
        echoed_tp = headers.get("X-Echo-Traceparent", "")
        self.assertTrue(echoed_tp.startswith(f"00-{client_trace_id}-"))
        self.assertTrue(echoed_tp.endswith("-01"))
        new_span_id = headers.get("X-Span-Id")
        self.assertEqual(echoed_tp, f"00-{client_trace_id}-{new_span_id}-01")
        self.assertNotEqual(new_span_id, client_parent_id)

        # Tracestate must be preserved
        self.assertEqual(headers.get("X-Echo-Tracestate"), client_ts)

    def test_03_otel_disabled(self):
        """Test that otel off does not inject traceparent."""
        status_line, headers, _ = self._request("/no_otel/test")
        self.assertIn("200 OK", status_line)
        self.assertNotIn("X-Echo-Traceparent", headers)


if __name__ == "__main__":
    filtered_argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.startswith("-")]
    unittest.main(argv=filtered_argv)
