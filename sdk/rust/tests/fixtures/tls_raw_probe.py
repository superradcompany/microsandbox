"""Verify opaque legacy TLS replay and rejection before any upstream bytes."""
import socket
import ssl
import sys
import time

port, named, fragmented = map(int, sys.argv[1:4])
kind = sys.argv[4]
ipv6 = int(sys.argv[5])
host = b"host.microsandbox.internal"
if kind == "legacy":
    body = bytearray(b"\x03\x02" + b"\x00" * 32 + b"\x00\x00\x02\x00\x2f\x01\x00")
    if named:
        entry = b"\x00" + len(host).to_bytes(2, "big") + host
        sni = len(entry).to_bytes(2, "big") + entry
        ext = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
        body.extend(len(ext).to_bytes(2, "big") + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    hello = b"\x16\x03\x02" + len(handshake).to_bytes(2, "big") + handshake
else:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    outgoing = ssl.MemoryBIO()
    client = ctx.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=host.decode())
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        # Expected: MemoryBIO has the ClientHello ready, with no peer input yet.
        pass
    hello = bytearray(outgoing.read())
    pos = 43
    pos += 1 + hello[pos]
    pos += 2 + int.from_bytes(hello[pos:pos+2], "big")
    pos += 1 + hello[pos]
    extensions = pos
    pos += 2
    while hello[pos:pos+2] != b"\x00\x00":
        pos += 4 + int.from_bytes(hello[pos+2:pos+4], "big")
    size = int.from_bytes(hello[pos+2:pos+4], "big")
    if kind == "duplicate-extension":
        hello.extend(hello[pos:pos+4+size])
    else:
        entry = b"\x00" + len(host).to_bytes(2, "big") + host
        if kind == "truncated-name":
            entry = b"\x00\xff\xff" + host
        if kind == "truncated-name":
            hello[pos+6:pos+4+size] = entry
            size = 2 + len(entry)
        else:
            hello[pos+4+size:pos+4+size] = entry
            size += len(entry)
        hello[pos+2:pos+4] = size.to_bytes(2, "big")
        hello[pos+4:pos+6] = (size-2).to_bytes(2, "big")
    hello[extensions:extensions+2] = (len(hello)-extensions-2).to_bytes(2, "big")
    hello[3:5] = (len(hello)-5).to_bytes(2, "big")
    hello[6:9] = (len(hello)-9).to_bytes(3, "big")
wire = bytes(hello)
if fragmented:
    wire = b""
    for start in range(5, len(hello), 17):
        part = hello[start:start+17]
        wire += hello[:3] + len(part).to_bytes(2, "big") + part
family = socket.AF_INET6 if ipv6 else socket.AF_INET
sock = socket.socket(family, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("fd42:6d73:62:ffff::1" if ipv6 else "172.30.255.1", port))
assert sock.family == family
assert sock.getsockname()[0] == ("fd42:6d73:62:ffff::2" if ipv6 else "172.30.255.2")
received = b""
try:
    for start in range(0, len(wire), 7 if fragmented else len(wire)):
        sock.sendall(wire[start:start+(7 if fragmented else len(wire))])
        if fragmented:
            time.sleep(0.001)
    while len(received) < len(wire):
        data = sock.recv(16384)
        if not data:
            break
        received += data
except (ConnectionResetError, BrokenPipeError):
    if kind == "legacy":
        raise
finally:
    sock.close()
if kind == "legacy":
    assert received == wire, (len(received), len(wire))
    print("forwarded", len(wire))
else:
    assert not received, "malformed hello was forwarded and echoed"
    print("blocked")
