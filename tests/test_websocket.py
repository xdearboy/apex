#!/usr/bin/env python3
"""Integration tests for Full-Duplex WebSockets Proxying in Apex.

Covers:
- HTTP/1.1 Upgrade: websocket handshake negotiation
- 101 Switching Protocols proxying
- Bidirectional full-duplex tunneling
- Text frames (opcode 0x01)
- Binary frames (opcode 0x02) including multi-KB payloads
- Ping / Pong frames (opcodes 0x09 / 0x0A)
- Rapid sequential frame streams
- Graceful Close handshake (opcode 0x08)
"""

import base64
import hashlib
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
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Socket closed unexpectedly; wanted {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def encode_frame(payload: bytes, opcode: int = 1, mask: bool = False) -> bytes:
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    length = len(payload)
    mask_flag = 0x80 if mask else 0x00

    if length <= 125:
        header.append(length | mask_flag)
    elif length <= 65535:
        header.append(126 | mask_flag)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127 | mask_flag)
        header.extend(struct.pack("!Q", length))

    if mask:
        mask_key = os.urandom(4)
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return bytes(header) + masked
    return bytes(header) + payload


def decode_frame(sock):
    header = recv_exact(sock, 2)
    opcode = header[0] & 0x0F
    has_mask = (header[1] & 0x80) != 0
    length = header[1] & 0x7F

    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]

    mask_key = recv_exact(sock, 4) if has_mask else None
    data = recv_exact(sock, length)

    if has_mask:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
    else:
        payload = data

    return opcode, payload


class WebSocketEchoServer:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(128)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            client_thread = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            client_thread.start()

    def _handle_client(self, conn):
        try:
            # Read handshake request
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                req += chunk

            # Extract Sec-WebSocket-Key
            lines = req.split(b"\r\n")
            ws_key = None
            for line in lines:
                if line.lower().startswith(b"sec-websocket-key:"):
                    ws_key = line.split(b":", 1)[1].strip()
                    break

            if not ws_key:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
                return

            accept_token = base64.b64encode(hashlib.sha1(ws_key + WS_GUID).digest())
            resp = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept_token + b"\r\n\r\n"
            )
            conn.sendall(resp)

            # Echo loop
            while True:
                opcode, payload = decode_frame(conn)
                if opcode == 0x08:  # Close
                    conn.sendall(encode_frame(payload, opcode=0x08, mask=False))
                    break
                elif opcode == 0x09:  # Ping -> Pong
                    conn.sendall(encode_frame(payload, opcode=0x0A, mask=False))
                elif opcode in (0x01, 0x02):  # Text or Binary
                    # Echo back as unmasked frame
                    conn.sendall(encode_frame(payload, opcode=opcode, mask=False))
        except (EOFError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


class WebSocketClient:
    def __init__(self, port, path="/ws", host="websocket.local"):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.key = base64.b64encode(os.urandom(16))
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key.decode('ascii')}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("utf-8")
        self.sock.sendall(handshake)

        # Read 101 response
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(1024)
            if not chunk:
                raise RuntimeError("Handshake failed: server closed socket")
            resp += chunk

        lines = resp.split(b"\r\n")
        status_line = lines[0].decode("ascii")
        if "101" not in status_line:
            raise RuntimeError(f"Handshake failed with status: {status_line}")

        expected_accept = base64.b64encode(hashlib.sha1(self.key + WS_GUID).digest())
        accept_found = False
        for line in lines:
            if line.lower().startswith(b"sec-websocket-accept:"):
                actual_accept = line.split(b":", 1)[1].strip()
                if actual_accept == expected_accept:
                    accept_found = True
                break
        if not accept_found:
            raise RuntimeError("Sec-WebSocket-Accept validation failed")

    def send_text(self, text: str):
        self.sock.sendall(encode_frame(text.encode("utf-8"), opcode=0x01, mask=True))

    def recv_text(self) -> str:
        opcode, payload = decode_frame(self.sock)
        if opcode != 0x01:
            raise ValueError(f"Expected text frame (0x01), got opcode {opcode}")
        return payload.decode("utf-8")

    def send_binary(self, data: bytes):
        self.sock.sendall(encode_frame(data, opcode=0x02, mask=True))

    def recv_binary(self) -> bytes:
        opcode, payload = decode_frame(self.sock)
        if opcode != 0x02:
            raise ValueError(f"Expected binary frame (0x02), got opcode {opcode}")
        return payload

    def send_ping(self, payload: bytes = b"ping"):
        self.sock.sendall(encode_frame(payload, opcode=0x09, mask=True))

    def recv_pong(self) -> bytes:
        opcode, payload = decode_frame(self.sock)
        if opcode != 0x0A:
            raise ValueError(f"Expected pong frame (0x0A), got opcode {opcode}")
        return payload

    def close(self):
        try:
            self.sock.sendall(encode_frame(b"", opcode=0x08, mask=True))
            # Wait for close response
            try:
                decode_frame(self.sock)
            except (EOFError, OSError):
                pass
        finally:
            self.sock.close()


class WebSocketProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws_backend_port = free_port()
        cls.ws_backend = WebSocketEchoServer(cls.ws_backend_port)

        cls.port = free_port()
        cls.workdir = tempfile.mkdtemp(prefix="apex_test_ws_")
        cls.conf_path = os.path.join(cls.workdir, "apex.conf")

        config = f"""
events {{}}
http {{
    server {{
        listen 127.0.0.1:{cls.port};
        server_name websocket.local;

        location /ws {{
            proxy_pass http://127.0.0.1:{cls.ws_backend_port};
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $http_connection;
            proxy_set_header Host $host;
        }}
    }}
}}
"""
        with open(cls.conf_path, "w") as f:
            f.write(config)

        cls.proc = subprocess.Popen([APEX, "-c", cls.conf_path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

        deadline = time.time() + START_TIMEOUT
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            cls.proc.kill()
            raise RuntimeError("Apex did not start in time for WebSocket test")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.ws_backend.stop()

    def test_01_handshake_and_text_echo(self):
        client = WebSocketClient(self.port, path="/ws")
        message = "Hello from Apex WebSocket client!"
        client.send_text(message)
        reply = client.recv_text()
        self.assertEqual(reply, message)
        client.close()

    def test_02_binary_frame_echo(self):
        client = WebSocketClient(self.port, path="/ws")
        # 16 KB binary payload
        payload = os.urandom(16384)
        client.send_binary(payload)
        echoed = client.recv_binary()
        self.assertEqual(echoed, payload)
        client.close()

    def test_03_ping_pong_control_frame(self):
        client = WebSocketClient(self.port, path="/ws")
        ping_token = b"apex-keepalive-ping"
        client.send_ping(ping_token)
        pong_token = client.recv_pong()
        self.assertEqual(pong_token, ping_token)
        client.close()

    def test_04_rapid_streaming_frames(self):
        client = WebSocketClient(self.port, path="/ws")
        count = 30
        for i in range(count):
            client.send_text(f"packet-{i:03d}")
        for i in range(count):
            reply = client.recv_text()
            self.assertEqual(reply, f"packet-{i:03d}")
        client.close()

    def test_05_clean_close_handshake(self):
        client = WebSocketClient(self.port, path="/ws")
        client.send_text("final message before close")
        reply = client.recv_text()
        self.assertEqual(reply, "final message before close")
        # Graceful close
        client.close()


def main():
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
