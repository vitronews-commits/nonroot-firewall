"""Loopback-only emulator acceptance fixture; no external network access."""
import socket
import threading


def echo(client):
    with client:
        client.settimeout(30)
        try:
            while data := client.recv(4096):
                client.sendall(data)
        except (OSError, TimeoutError):
            pass


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


threading.Thread(target=tcp, daemon=True).start()
udp()
