"""Streams opened by the connection module clean up after failed handshakes."""

import socket
import ssl
import threading

import pytest

from certmonitor.protocol_handlers import connection
from certmonitor.protocol_handlers.connection import open_stream, open_tls_stream
from certmonitor.protocol_handlers.starttls import StartTLSError


def test_failed_handshake_closes_the_plaintext_socket(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    def hang_up():
        conn, _ = listener.accept()
        conn.close()

    threading.Thread(target=hang_up, daemon=True).start()

    opened = []
    real_create_connection = socket.create_connection

    def recording(address, timeout=None):
        sock = real_create_connection(address, timeout=timeout)
        opened.append(sock)
        return sock

    monkeypatch.setattr(connection.socket, "create_connection", recording)
    with pytest.raises(OSError):
        open_tls_stream(
            "127.0.0.1",
            port,
            1,
            ssl.create_default_context(),
            server_hostname="localhost",
        )
    listener.close()
    assert len(opened) == 1
    assert opened[0].fileno() == -1


def test_refused_preamble_closes_the_plaintext_socket(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    def greet_then_hang_up():
        conn, _ = listener.accept()
        conn.sendall(b"220 fake ESMTP\r\n")
        conn.close()

    threading.Thread(target=greet_then_hang_up, daemon=True).start()

    opened = []
    real_create_connection = socket.create_connection

    def recording(address, timeout=None):
        sock = real_create_connection(address, timeout=timeout)
        opened.append(sock)
        return sock

    monkeypatch.setattr(connection.socket, "create_connection", recording)
    with pytest.raises(StartTLSError):
        open_stream("127.0.0.1", port, 1, starttls="smtp")
    listener.close()
    assert len(opened) == 1
    assert opened[0].fileno() == -1
