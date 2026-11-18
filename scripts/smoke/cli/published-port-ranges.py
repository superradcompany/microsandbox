#!/usr/bin/env python3
"""Forward three distinct host ports to three guest ports over TCP and UDP.

Run with MSB_PATH pointing to a net-enabled candidate CLI and working VM artifacts.
Uses the configured MSB_HOME/image cache and removes only its uniquely named sandbox.
PORT_RANGE_IMAGE defaults to python:3.12-alpine; host Python needs no extra packages.
"""

import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


GUEST_START = 18080
SERVER = """
import socket, threading, time
def serve(port, udp):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', port))
        if not udp:
            s.listen()
        while True:
            if udp:
                data, peer = s.recvfrom(4096)
                s.sendto(str(port).encode() + b':' + data, peer)
            else:
                conn, peer = s.accept()
                with conn, conn.makefile('rb') as reader:
                    data = reader.readline().removesuffix(b'\\n')
                    conn.sendall(str(port).encode() + b':' + data)
for port in range(18080, 18083):
    for udp in (False, True):
        threading.Thread(target=serve, args=(port, udp), daemon=True).start()
while True:
    time.sleep(1)
"""


def available_host_range():
    # Hold all six sockets while probing; release before launching msb.
    # Another process can still race us after release, in which case forwarding fails.
    for start in range(28080, 29080, 3):
        sockets = []
        try:
            for port in range(start, start + 3):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    sock = socket.socket(socket.AF_INET, kind)
                    sockets.append(sock)
                    sock.bind(('127.0.0.1', port))
            return start
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError('no free three-port TCP/UDP host range')


def main():
    binary = str(Path(os.environ['MSB_PATH']).resolve(strict=True))
    name = 'port-range-smoke-' + uuid.uuid4().hex[:12]
    host_start = available_host_range()
    image = os.environ.get('PORT_RANGE_IMAGE', 'python:3.12-alpine')
    mapping = f'127.0.0.1:{host_start}-{host_start + 2}:{GUEST_START}-{GUEST_START + 2}'
    with tempfile.TemporaryDirectory(prefix='msb-port-range-') as directory:
        config = Path(directory) / 'network.yaml'
        config.write_text(f'network:\n  policy: open\n  ports: ["{mapping}/udp"]\n', encoding='utf-8')
        try:
            # CLI covers TCP expansion; YAML covers UDP expansion in the same VM.
            subprocess.run([binary, 'run', image, '--name', name, '--detach',
                            '--conf', str(config), '-p', mapping + '/tcp',
                            '--', 'python', '-u', '-c', SERVER], check=True, timeout=240)
            for udp in (False, True):
                for offset in range(3):
                    host = host_start + offset
                    guest = GUEST_START + offset
                    payload = f'{name}-{udp}-{offset}'.encode()
                    expected = str(guest).encode() + b':' + payload
                    deadline = time.monotonic() + 20
                    while True:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
                                sock.settimeout(1)
                                sock.connect(('127.0.0.1', host))
                                sock.sendall(payload if udp else payload + b'\n')
                                if udp:
                                    response = sock.recv(4096)
                                else:
                                    response = b''
                                    while len(response) < len(expected):
                                        chunk = sock.recv(4096)
                                        if not chunk:
                                            break
                                        response += chunk
                            if not response:
                                raise ConnectionError("guest listener is not ready")
                            assert response == expected, (host, guest, response, expected)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.1)
                    print(f'PASS {"UDP" if udp else "TCP"} {host} -> {guest}: {response!r}', flush=True)
        finally:
            subprocess.run([binary, 'remove', '--force', name], check=True, timeout=60)


if __name__ == '__main__':
    main()
