"""Loopback-only emulator acceptance fixture; no external network access."""
import socket
import threading


def echo(client):
    with client:
        client.settimeout(30)
        try:
            count = 0
            while data := client.recv(4096):
                count += len(data)
                client.sendall(data)
            # Explicit half-close: exercise FIN semantics through emulator NAT, not only close().
            client.shutdown(socket.SHUT_WR)
        except (OSError, TimeoutError) as error:
            print(f"TCP_FIXTURE_ERROR {type(error).__name__}: {error}", flush=True)


def tcp():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 28080))
        server.listen(8)
        while True:
            client, _ = server.accept()
            threading.Thread(target=echo, args=(client,), daemon=True).start()


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 28081))
        while True:
            data, address = server.recvfrom(4096)
            server.sendto(data, address)


def dns_answer(query):
    # Bounded RFC 1035 fixture: one A/IN question, no compression in queries.
    if len(query) < 17 or len(query) > 512 or query[4:6] != b"\x00\x01":
        raise ValueError("Invalid DNS question")
    pos = 12
    while True:
        size = query[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size >= len(query):
            raise ValueError("Invalid DNS label")
        pos += size
    if query[pos:] != b"\x00\x01\x00\x01":
        raise ValueError("Fixture supports only one A/IN question")
    return query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x7b"


def dns_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 28082))
        while True:
            query, address = server.recvfrom(513)
            try:
                server.sendto(dns_answer(query), address)
            except (ValueError, IndexError):
                pass


def dns_tcp_client(client):
    def read_exact(size):
        result = b""
        while len(result) < size:
            chunk = client.recv(size - len(result))
            if not chunk:
                raise EOFError()
            result += chunk
        return result
    with client:
        client.settimeout(15)
        try:
            size = int.from_bytes(read_exact(2), "big")
            if size > 512:
                return
            answer = dns_answer(read_exact(size))
            client.sendall(len(answer).to_bytes(2, "big") + answer)
        except (OSError, ValueError, IndexError, EOFError):
            pass


def dns_tcp():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 28083))
        server.listen(8)
        while True:
            client, _ = server.accept()
            threading.Thread(target=dns_tcp_client, args=(client,), daemon=True).start()


def lockdown_sink():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 28084))
        while True:
            data, address = server.recvfrom(128)
            if data.startswith(b"lockdown-") and data[9:].isalnum():
                print("LOCKDOWN_LEAK " + data[9:].decode("ascii"), flush=True)
                server.sendto(data, address)


threading.Thread(target=lockdown_sink, daemon=True).start()
threading.Thread(target=dns_udp, daemon=True).start()
threading.Thread(target=dns_tcp, daemon=True).start()
threading.Thread(target=tcp, daemon=True).start()
udp()
