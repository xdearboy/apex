#!/usr/bin/env python3
"""
Test HTTP/3 and QUIC Transport Engine for Apex (RFC 9000, 9114, 9204)
Tests:
- HTTP/3 GET request (curl --http3-only)
- HTTP/3 response headers and body
- Alt-Svc advertisement on TLS endpoints
- Multiple sequential and concurrent HTTP/3 requests
"""

import concurrent.futures
import http.client
import http.server
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

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

class TestHttp3(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='apex_h3_test_')
        self.port = find_free_port()
        self.conf_path = os.path.join(self.tmp_dir, 'apex.conf')
        self.cert_path = os.path.join(self.tmp_dir, 'server.crt')
        self.key_path = os.path.join(self.tmp_dir, 'server.key')
        self.apex_bin = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else './apex'

        # Generate self-signed test certificate
        subprocess.run([
            'openssl', 'req', '-x509', '-nodes', '-days', '1',
            '-newkey', 'rsa:2048',
            '-keyout', self.key_path,
            '-out', self.cert_path,
            '-subj', '/CN=localhost'
        ], check=True, capture_output=True)

        # Check curl with HTTP/3 support
        curl_ver = subprocess.run(['curl', '--version'], capture_output=True, text=True)
        if 'HTTP3' not in curl_ver.stdout:
            self.skipTest("curl does not support HTTP3")

    def tearDown(self):
        if hasattr(self, 'proc') and self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def start_apex(self, conf_content):
        with open(self.conf_path, 'w') as f:
            f.write(conf_content)
        self.proc = subprocess.Popen(
            [self.apex_bin, '-c', self.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(0.4)
        poll_res = self.proc.poll()
        if poll_res is not None:
            self.fail(f"Apex died on start with exit code {poll_res}: {self.proc.stderr.read()}")

    def test_http3_basic(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port} tls;
        tls {{
            certificate "{self.cert_path}";
            private_key "{self.key_path}";
        }}
        server_name localhost;

        location / {{
            return 200 "Hello from Apex HTTP/3\\n";
        }}

        location /api/test {{
            return 200 "API over HTTP/3 OK\\n";
        }}
    }}
}}
"""
        self.start_apex(conf)

        # 1. Test Alt-Svc advertisement on standard TLS connection
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=5)
        conn.request('GET', '/')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        alt_svc = resp.getheader('Alt-Svc')
        self.assertIsNotNone(alt_svc, "Alt-Svc header must be advertised on TLS endpoints")
        self.assertIn('h3=', alt_svc)
        conn.close()

        # 2. Test native HTTP/3 GET request via curl --http3-only
        res = subprocess.run([
            'curl', '-s', '-S', '--http3-only', '-k',
            '-i', f'https://127.0.0.1:{self.port}/'
        ], capture_output=True, text=True, timeout=5)

        self.assertEqual(res.returncode, 0, f"curl HTTP/3 failed: {res.stderr}")
        self.assertIn("HTTP/3 200", res.stdout)
        self.assertIn("server: apex", res.stdout.lower())
        self.assertIn("Hello from Apex HTTP/3", res.stdout)

        # 3. Test HTTP/3 request to subpath
        res_api = subprocess.run([
            'curl', '-s', '-S', '--http3-only', '-k',
            f'https://127.0.0.1:{self.port}/api/test'
        ], capture_output=True, text=True, timeout=5)

        self.assertEqual(res_api.returncode, 0, f"curl HTTP/3 /api/test failed: {res_api.stderr}")
        self.assertEqual(res_api.stdout, "API over HTTP/3 OK\n")

    def test_http3_multiple_requests(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port} tls;
        tls {{
            certificate "{self.cert_path}";
            private_key "{self.key_path}";
        }}
        server_name localhost;

        location /ping {{
            return 200 "pong\\n";
        }}
    }}
}}
"""
        self.start_apex(conf)

        for i in range(5):
            res = subprocess.run([
                'curl', '-s', '-S', '--http3-only', '-k',
                f'https://127.0.0.1:{self.port}/ping'
            ], capture_output=True, text=True, timeout=5)
            self.assertEqual(res.returncode, 0, f"HTTP/3 ping #{i} failed: {res.stderr}")
            self.assertEqual(res.stdout, "pong\n")

    def test_http3_concurrent_requests(self):
        conf = f"""
http {{
    server {{
        listen 127.0.0.1:{self.port} tls;
        tls {{
            certificate "{self.cert_path}";
            private_key "{self.key_path}";
        }}
        server_name localhost;

        location /ping {{
            return 200 "pong\\n";
        }}
    }}
}}
"""
        self.start_apex(conf)

        def make_req(idx):
            res = subprocess.run([
                'curl', '-s', '-S', '--http3-only', '-k',
                f'https://127.0.0.1:{self.port}/ping'
            ], capture_output=True, text=True, timeout=5)
            return (res.returncode, res.stdout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(make_req, i) for i in range(16)]
            for f in concurrent.futures.as_completed(futures):
                code, out = f.result()
                self.assertEqual(code, 0)
                self.assertEqual(out, "pong\n")

    def test_http3_reverse_proxy(self):
        backend_port = find_free_port()

        class BackendHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = f"Backend handled {self.path}\\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        backend = http.server.HTTPServer(('127.0.0.1', backend_port), BackendHandler)
        t = threading.Thread(target=backend.serve_forever, daemon=True)
        t.start()

        conf = f"""
http {{
    upstream test_backend {{
        server 127.0.0.1:{backend_port};
    }}

    server {{
        listen 127.0.0.1:{self.port} tls;
        tls {{
            certificate "{self.cert_path}";
            private_key "{self.key_path}";
        }}
        server_name localhost;

        location /proxy/ {{
            proxy_pass test_backend;
        }}
    }}
}}
"""
        self.start_apex(conf)

        try:
            res = subprocess.run([
                'curl', '-s', '-S', '--http3-only', '-k',
                f'https://127.0.0.1:{self.port}/proxy/hello'
            ], capture_output=True, text=True, timeout=5)
            self.assertEqual(res.returncode, 0, f"curl HTTP/3 proxy failed: {res.stderr}")
            self.assertIn("Backend handled /proxy/hello", res.stdout)
        finally:
            backend.shutdown()
            backend.server_close()

if __name__ == '__main__':
    args = [sys.argv[0]]
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        args.extend(sys.argv[2:])
    else:
        args.extend(sys.argv[1:])
    unittest.main(argv=args)
