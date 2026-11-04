"""Verify host fixtures before Android starts; no external DNS/network access."""
import socket
import struct
import time

label = b"firewall-test"
query = struct.pack("!6H", 0x4E52, 0x0100, 1, 0, 0, 0) + bytes([len(label)]) + label + b"\x07invalid\x00\x00\x01\x00\x01"

def read_exact(sock, size):
    result = b""
    while len(result) < size:
        data = sock.recv(size - len(result))
        assert data
        result += data
    return result

for attempt in range(20):
    try:
        for port in (53, 28082):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                client.sendto(query, ("127.0.0.1", port))
                answer, _ = client.recvfrom(512)
                assert answer[:2] == query[:2] and answer[-4:] == b"\xc0\x00\x02\x7b"
        for port in (53, 28083):
            with socket.create_connection(("127.0.0.1", port), 1) as client:
                client.sendall(len(query).to_bytes(2, "big") + query)
                answer = read_exact(client, int.from_bytes(read_exact(client, 2), "big"))
                assert answer[-4:] == b"\xc0\x00\x02\x7b"
        with socket.create_connection(("127.0.0.1", 28080), 1) as client:
            client.sendall(b"fixture-test")
            client.shutdown(socket.SHUT_WR)
            assert read_exact(client, 12) == b"fixture-test"
            assert client.recv(1) == b""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(b"fixture-test", ("127.0.0.1", 28081))
            assert client.recv(128) == b"fixture-test"
        print("Verified: isolated DNS UDP/TCP, TCP half-close and UDP fixtures are ready.")
        break
    except (OSError, AssertionError):
        if attempt == 19:
            raise
        time.sleep(0.1)
