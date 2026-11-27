#!/usr/bin/env python3
"""Integration tests for open_file_cache zero-copy static file engine in Apex.

Covers:
- open_file_cache max=N [inactive=time]
- open_file_cache_valid <time>
- open_file_cache_min_uses <count>
- open_file_cache_errors on|off
- Preconditions (ETag, 304 Not Modified, If-None-Match, If-Modified-Since)
- Large file sendfile(2) descriptor sharing (>4MB)
- Negative caching (404 Not Found caching)
"""

import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

APEX = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("./apex")
START_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestOpenFileCache(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.www_dir = os.path.join(self.temp_dir.name, "www")
        os.makedirs(self.www_dir, exist_ok=True)
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
            text=True,
        )

        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                stdout, stderr = self.proc.communicate()
                raise RuntimeError(
                    f"Apex failed to start (exit code {self.proc.returncode}):\n{stderr}\n{stdout}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(0.05)

        self.proc.terminate()
        stdout, stderr = self.proc.communicate()
        raise TimeoutError(f"Apex did not bind to port {self.port} in time:\n{stderr}\n{stdout}")

    def test_open_file_cache_hits_and_metadata(self):
        # Create static test file
        test_file = os.path.join(self.www_dir, "test.txt")
        content = b"Hello from Apex Open File Cache! Zero-copy performance."
        with open(test_file, "wb") as f:
            f.write(content)

        conf = f"""
events {{}}
http {{
    open_file_cache max=1000 inactive=30s;
    open_file_cache_valid 60s;
    open_file_cache_min_uses 1;
    open_file_cache_errors on;

    server {{
        listen {self.port};
        location / {{
            root {self.www_dir};
        }}
    }}
}}
"""
        self.start_apex(conf)

        # First request (populate cache)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/test.txt")
        res1 = conn.getresponse()
        self.assertEqual(res1.status, 200)
        body1 = res1.read()
        self.assertEqual(body1, content)
        etag1 = res1.getheader("ETag")
        last_mod1 = res1.getheader("Last-Modified")
        self.assertIsNotNone(etag1)
        self.assertIsNotNone(last_mod1)

        # Second request (cache hit)
        conn.request("GET", "/test.txt")
        res2 = conn.getresponse()
        self.assertEqual(res2.status, 200)
        body2 = res2.read()
        self.assertEqual(body2, content)
        self.assertEqual(res2.getheader("ETag"), etag1)
        self.assertEqual(res2.getheader("Last-Modified"), last_mod1)

        # Third request with If-None-Match (304 Not Modified hit)
        conn.request("GET", "/test.txt", headers={"If-None-Match": etag1})
        res3 = conn.getresponse()
        self.assertEqual(res3.status, 304)
        self.assertEqual(res3.read(), b"")

        # Fourth request with If-Modified-Since (304 Not Modified hit)
        conn.request("GET", "/test.txt", headers={"If-Modified-Since": last_mod1})
        res4 = conn.getresponse()
        self.assertEqual(res4.status, 304)
        self.assertEqual(res4.read(), b"")

        conn.close()

    def test_open_file_cache_negative_caching(self):
        conf = f"""
events {{}}
http {{
    server {{
        listen {self.port};
        location / {{
            root {self.www_dir};
            open_file_cache max=500 inactive=20s;
            open_file_cache_errors on;
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)

        # Request missing file: should return 404 and cache negative hit
        conn.request("GET", "/does_not_exist.html")
        res1 = conn.getresponse()
        self.assertEqual(res1.status, 404)
        res1.read()

        # Second request: negative hit from open_file_cache
        conn.request("GET", "/does_not_exist.html")
        res2 = conn.getresponse()
        self.assertEqual(res2.status, 404)
        res2.read()

        conn.close()

    def test_open_file_cache_large_file_sendfile(self):
        # Create large 5MB file (> APEX_FILE_CACHE_MAX_MMAP 4MB) to trigger sendfile descriptor sharing
        large_file = os.path.join(self.www_dir, "large.dat")
        chunk = b"A" * 65536
        large_size = 5 * 1024 * 1024
        with open(large_file, "wb") as f:
            for _ in range(large_size // len(chunk)):
                f.write(chunk)

        conf = f"""
events {{}}
http {{
    open_file_cache max=100;
    server {{
        listen {self.port};
        location / {{
            root {self.www_dir};
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)

        # First request (open & cache fd)
        conn.request("GET", "/large.dat")
        res1 = conn.getresponse()
        self.assertEqual(res1.status, 200)
        self.assertEqual(int(res1.getheader("Content-Length")), large_size)
        data1 = res1.read()
        self.assertEqual(len(data1), large_size)

        # Second request (shared cached fd via sendfile)
        conn.request("GET", "/large.dat")
        res2 = conn.getresponse()
        self.assertEqual(res2.status, 200)
        data2 = res2.read()
        self.assertEqual(len(data2), large_size)

        # Range request on cached descriptor
        conn.request("GET", "/large.dat", headers={"Range": "bytes=0-1023"})
        res3 = conn.getresponse()
        self.assertEqual(res3.status, 206)
        self.assertEqual(res3.getheader("Content-Range"), f"bytes 0-1023/{large_size}")
        self.assertEqual(len(res3.read()), 1024)

        conn.close()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
