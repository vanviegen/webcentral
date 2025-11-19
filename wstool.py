#!/usr/bin/env python3
"""
wstool.py - A simple WebSocket client and server tool using only the Python standard library.
Implements RFC 6455.
"""

import argparse
import base64
import hashlib
import http.client
import os
import select
import socket
import struct
import sys
import threading
import time
from urllib.parse import urlparse

# Constants
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

class WebSocketError(Exception):
    pass

def create_frame(data, opcode=OP_TEXT, mask=False):
    """Create a WebSocket frame."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    length = len(data)
    frame = bytearray()
    
    # Fin + Opcode
    frame.append(0x80 | opcode)
    
    # Mask + Length
    if length < 126:
        payload_len = length
    elif length < 65536:
        payload_len = 126
    else:
        payload_len = 127
        
    if mask:
        frame.append(0x80 | payload_len)
    else:
        frame.append(payload_len)
        
    if payload_len == 126:
        frame.extend(struct.pack("!H", length))
    elif payload_len == 127:
        frame.extend(struct.pack("!Q", length))
        
    if mask:
        masking_key = os.urandom(4)
        frame.extend(masking_key)
        masked_data = bytearray(length)
        for i in range(length):
            masked_data[i] = data[i] ^ masking_key[i % 4]
        frame.extend(masked_data)
    else:
        frame.extend(data)
        
    return frame

def read_frame(sock):
    """Read a WebSocket frame from a socket."""
    # Read first 2 bytes
    head = sock.recv(2)
    if len(head) < 2:
        return None, None
        
    byte1, byte2 = struct.unpack("!BB", head)
    
    fin = (byte1 & 0x80) != 0
    opcode = byte1 & 0x0F
    masked = (byte2 & 0x80) != 0
    payload_len = byte2 & 0x7F
    
    if payload_len == 126:
        data = sock.recv(2)
        if len(data) < 2: return None, None
        payload_len = struct.unpack("!H", data)[0]
    elif payload_len == 127:
        data = sock.recv(8)
        if len(data) < 8: return None, None
        payload_len = struct.unpack("!Q", data)[0]
        
    masking_key = None
    if masked:
        masking_key = sock.recv(4)
        if len(masking_key) < 4: return None, None
        
    payload = b""
    remaining = payload_len
    while remaining > 0:
        chunk = sock.recv(min(4096, remaining))
        if not chunk: return None, None
        payload += chunk
        remaining -= len(chunk)
        
    if masked:
        unmasked = bytearray(len(payload))
        for i in range(len(payload)):
            unmasked[i] = payload[i] ^ masking_key[i % 4]
        payload = unmasked
        
    return opcode, payload

class WebSocketClient:
    def __init__(self, url, connect_host=None, connect_port=None, host_header=None):
        """
        Create a WebSocket client.
        
        Args:
            url: WebSocket URL (ws://... or wss://...)
            connect_host: Override the host to connect to (default: derived from URL)
            connect_port: Override the port to connect to (default: derived from URL)
            host_header: Override the Host header (default: derived from URL)
        """
        self.url = url
        self.connect_host = connect_host
        self.connect_port = connect_port
        self.host_header = host_header
        self.sock = None
        self.connected = False
        
    def connect(self):
        parsed = urlparse(self.url)
        host = self.connect_host or parsed.hostname
        port = self.connect_port or parsed.port or (443 if parsed.scheme == 'wss' else 80)
        path = parsed.path or '/'
        
        # For Host header, use custom value if provided, otherwise derive from URL
        if self.host_header:
            host_header = self.host_header
        else:
            url_host = parsed.hostname
            url_port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
            # Only include port in Host header if it's non-standard
            if (parsed.scheme == 'ws' and url_port != 80) or (parsed.scheme == 'wss' and url_port != 443):
                host_header = f"{url_host}:{url_port}"
            else:
                host_header = url_host
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        
        key = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        
        self.sock.sendall(request.encode('utf-8'))
        
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketError("Connection closed during handshake")
            response += chunk
            
        headers = response.decode('utf-8').split('\r\n')
        if "HTTP/1.1 101" not in headers[0]:
            raise WebSocketError(f"Handshake failed: {headers[0]}")
            
        self.connected = True
        
    def send(self, data):
        if not self.connected:
            raise WebSocketError("Not connected")
        frame = create_frame(data, mask=True)
        self.sock.sendall(frame)
        
    def recv(self):
        if not self.connected:
            raise WebSocketError("Not connected")
        opcode, payload = read_frame(self.sock)
        if opcode == OP_CLOSE:
            self.close()
            return None
        return payload
        
    def close(self):
        if self.connected:
            try:
                self.sock.sendall(create_frame(b"", opcode=OP_CLOSE, mask=True))
                self.sock.close()
            except:
                pass
            self.connected = False

class WebSocketServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Listening on {self.host}:{self.port}", flush=True)
        
        while True:
            client, addr = self.sock.accept()
            print(f"Connection from {addr}", flush=True)
            threading.Thread(target=self.handle_client, args=(client,)).start()
            
    def handle_client(self, client):
        try:
            # Handshake - read until we get complete HTTP request
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                data += chunk
            
            # Parse headers (normalize to lowercase for case-insensitive lookup)
            request_str = data.decode('utf-8')
            headers = {}
            lines = request_str.split('\r\n')
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
                    
            if 'sec-websocket-key' not in headers:
                client.close()
                return
                
            key = headers['sec-websocket-key']
            accept_key = base64.b64encode(hashlib.sha1((key + GUID).encode('utf-8')).digest()).decode('utf-8')
            
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n"
                "\r\n"
            )
            client.sendall(response.encode('utf-8'))
            
            # Echo loop
            while True:
                opcode, payload = read_frame(client)
                if opcode is None or opcode == OP_CLOSE:
                    break
                
                if opcode == OP_TEXT or opcode == OP_BINARY:
                    # Echo back
                    # Server does NOT mask frames
                    client.sendall(create_frame(payload, opcode=opcode, mask=False))
                    # Log for tests
                    try:
                        print(f"Echoed: {payload.decode('utf-8')}", flush=True)
                    except:
                        print(f"Echoed binary: {len(payload)} bytes", flush=True)
                        
        except Exception as e:
            print(f"Error: {e}", flush=True)
            import traceback
            traceback.print_exc()
        finally:
            client.close()

def run_client(url, message=None):
    client = WebSocketClient(url)
    try:
        client.connect()
        print(f"Connected to {url}")
        
        if message:
            client.send(message)
            response = client.recv()
            print(f"Received: {response.decode('utf-8')}")
        else:
            # Interactive mode
            import sys
            while True:
                line = sys.stdin.readline()
                if not line: break
                client.send(line.strip())
                response = client.recv()
                if response:
                    print(f"Received: {response.decode('utf-8')}")
                else:
                    break
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

def run_server(port):
    server = WebSocketServer(port=port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nStopping server")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='WebSocket Tool')
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Run WebSocket echo server')
    server_parser.add_argument('port', type=int, help='Port to listen on')
    
    # Client command
    client_parser = subparsers.add_parser('client', help='Run WebSocket client')
    client_parser.add_argument('url', help='WebSocket URL')
    client_parser.add_argument('--message', '-m', help='Single message to send')
    
    args = parser.parse_args()
    
    if args.command == 'server':
        run_server(args.port)
    elif args.command == 'client':
        run_client(args.url, args.message)
