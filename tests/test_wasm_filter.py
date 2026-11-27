#!/usr/bin/env python3
"""
Test WasmEdge 0.14.1 WebAssembly Filter for Apex
Tests:
- wasm_filter returning 1 -> 403 Forbidden
- wasm_filter calling proxy_set_header -> response header injected
- wasm_filter calling proxy_exit(418) -> returns 418
"""

import http.client
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

class TestWasmFilter(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='apex_wasm_test_')
        self.port = find_free_port()
        self.conf_path = os.path.join(self.tmp_dir, 'apex.conf')
        self.apex_bin = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else './apex'

        # Check if wat2wasm is available
        self.wat2wasm = shutil.which('wat2wasm')
        if not self.wat2wasm:
            self.skipTest("wat2wasm not found in PATH")

    def tearDown(self):
        if hasattr(self, 'proc') and self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def compile_wat(self, wat_code, wasm_filename):
        wat_path = os.path.join(self.tmp_dir, wasm_filename + '.wat')
        wasm_path = os.path.join(self.tmp_dir, wasm_filename + '.wasm')
        with open(wat_path, 'w') as f:
            f.write(wat_code)
        res = subprocess.run([self.wat2wasm, wat_path, '-o', wasm_path], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"wat2wasm failed: {res.stderr}")
        return wasm_path

    def start_apex(self, conf_content):
        with open(self.conf_path, 'w') as f:
            f.write(conf_content)
        self.proc = subprocess.Popen(
            [self.apex_bin, '-c', self.conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(0.3)
        poll_res = self.proc.poll()
        if poll_res is not None:
            self.fail(f"Apex died on start with exit code {poll_res}: {self.proc.stderr.read()}")

    def test_wasm_filters(self):
        # 1. Block filter: returns 1 (deny)
        wat_deny = """
(module
  (func (export "filter_run") (result i32)
    i32.const 1
  )
)
"""
        wasm_deny = self.compile_wat(wat_deny, "deny")

        # 2. Allow filter: returns 0 (allow)
        wat_allow = """
(module
  (func (export "filter_run") (result i32)
    i32.const 0
  )
)
"""
        wasm_allow = self.compile_wat(wat_allow, "allow")

        # 3. Header modifier filter: calls proxy_set_header("X-Wasm", "Enabled")
        wat_header = """
(module
  (import "env" "proxy_set_header" (func $proxy_set_header (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "X-Wasm")
  (data (i32.const 16) "Enabled")
  (func (export "filter_run") (result i32)
    ;; proxy_set_header(name_ptr=0, name_len=6, val_ptr=16, val_len=7)
    i32.const 0
    i32.const 6
    i32.const 16
    i32.const 7
    call $proxy_set_header
    drop
    i32.const 0
  )
)
"""
        wasm_header = self.compile_wat(wat_header, "header")

        # 4. Custom status filter: calls proxy_exit(418)
        wat_teapot = """
(module
  (import "env" "proxy_exit" (func $proxy_exit (param i32) (result i32)))
  (func (export "filter_run") (result i32)
    i32.const 418
    call $proxy_exit
    drop
    i32.const 418
  )
)
"""
        wasm_teapot = self.compile_wat(wat_teapot, "teapot")

        conf = f"""
http {{
    server {{
        listen {self.port};
        server_name localhost;

        location /blocked {{
            wasm_filter "{wasm_deny}";
            return 200 "Should not see this\\n";
        }}

        location /allowed {{
            wasm_filter "{wasm_allow}";
            return 200 "Allowed by Wasm\\n";
        }}

        location /with_header {{
            wasm_filter "{wasm_header}";
            return 200 "Header added\\n";
        }}

        location /teapot {{
            wasm_filter "{wasm_teapot}";
            return 200 "Teapot\\n";
        }}
    }}
}}
"""
        self.start_apex(conf)

        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)

        # 1. /blocked -> 403 Forbidden
        conn.request('GET', '/blocked')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        resp.read()

        # 2. /allowed -> 200 OK
        conn.request('GET', '/allowed')
        resp = conn.getresponse()
        body = resp.read().decode('utf-8')
        self.assertEqual(resp.status, 200)
        self.assertEqual(body, "Allowed by Wasm\n")

        # 3. /with_header -> 200 OK + X-Wasm: Enabled
        conn.request('GET', '/with_header')
        resp = conn.getresponse()
        body = resp.read().decode('utf-8')
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader('X-Wasm'), 'Enabled')
        self.assertEqual(body, "Header added\n")

        # 4. /teapot -> 418
        conn.request('GET', '/teapot')
        resp = conn.getresponse()
        self.assertEqual(resp.status, 418)
        resp.read()

        conn.close()

if __name__ == '__main__':
    args = [sys.argv[0]]
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        args.extend(sys.argv[2:])
    else:
        args.extend(sys.argv[1:])
    unittest.main(argv=args)
