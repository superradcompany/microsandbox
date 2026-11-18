"""Guest-side TLS probe: control record fragmentation and verify real responses."""
import ipaddress
import socket
import ssl
import sys
import time

port, version, named, fragmented, blocked, bypass, ipv6 = map(int, sys.argv[1:])
host = "probe.example"
# Populate DNS evidence even for the no-SNI connection.
family = socket.AF_INET6 if ipv6 else socket.AF_INET
address = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0][4]
ip = address[0]
assert ip == ("fd42:6d73:62:ffff::1" if ipv6 else "172.30.255.1"), ip
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # CA/IP verification has its own independent matrix.
ctx.minimum_version = ctx.maximum_version = (
    ssl.TLSVersion.TLSv1_2 if version == 12 else ssl.TLSVersion.TLSv1_3
)
incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
client = ctx.wrap_bio(incoming, outgoing, server_hostname=host if named else None)
sock = socket.socket(family, socket.SOCK_STREAM)
sock.settimeout(8)
sock.connect(address)
assert sock.family == family
assert sock.getsockname()[0] == ("fd42:6d73:62:ffff::2" if ipv6 else "172.30.255.2")


def flush():
    data = outgoing.read()
    if data:
        sock.sendall(data)


def receive():
    data = sock.recv(16384)
    if not data:
        raise EOFError("peer closed")
    incoming.write(data)


try:
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        # Expected: MemoryBIO has the ClientHello ready, with no peer input yet.
        pass
    hello = outgoing.read()
    assert hello and hello[0] == 22
    if fragmented:
        wire = bytearray()
        while hello:
            length = int.from_bytes(hello[3:5], "big")
            payload = hello[5 : 5 + length]
            assert len(payload) == length
            for start in range(0, length, 17):
                part = payload[start : start + 17]
                wire.extend(hello[:3] + len(part).to_bytes(2, "big") + part)
            hello = hello[5 + length :]
        # Separate TCP writes as well as TLS records, including header splits.
        for start in range(0, len(wire), 7):
            sock.sendall(wire[start : start + 7])
            time.sleep(0.001)
    else:
        sock.sendall(hello)
    while True:
        try:
            client.do_handshake()
            flush()
            break
        except ssl.SSLWantReadError:
            flush()
            receive()
    assert client.version() == ("TLSv1.2" if version == 12 else "TLSv1.3")
    assert not blocked, "strict bypass denial completed a TLS handshake"
    with open("/tmp/upstream.der", "rb") as certificate:
        assert (client.getpeercert(binary_form=True) == certificate.read()) == bool(bypass)
    # Expanded, bracketed IPv6 must match the compressed destination identity.
    authority = host if named else (f"[{ipaddress.ip_address(ip).exploded}]" if ipv6 else ip)
    request = (
        f"POST /probe HTTP/1.1\r\nHost: {authority}\r\n"
        "Content-Length: 5\r\nConnection: close\r\n\r\nprobe"
    ).encode()
    client.write(request)
    flush()
    response = bytearray()
    while b"\r\n\r\n" not in response or not response.endswith(b"ok"):
        try:
            data = client.read(16384)
            if not data:
                break
            response.extend(data)
            if b"403 Forbidden" in response:
                break
        except ssl.SSLWantReadError:
            flush()
            receive()
    assert response.startswith(b"HTTP/1.1 200") and response.endswith(b"ok"), response
    print(client.version(), "200")
except (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError) as error:
    if not blocked:
        raise
    print("blocked", type(error).__name__)
finally:
    sock.close()
