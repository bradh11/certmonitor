# protocol_handlers/connection.py

"""Open the plaintext or TLS stream a handler needs, in one place.

Every connection CertMonitor makes takes the same steps: reach the host, run
a STARTTLS preamble when the service needs one, and, for TLS, wrap the socket
with the caller's context. `open_stream` and `open_tls_stream` perform those
steps so the handlers, protocol detection, service discovery, and the
verified trust handshake never assemble a connection on their own.
"""

from __future__ import annotations

import socket
import ssl

from . import starttls as starttls_negotiation


def open_stream(
    host: str, port: int, timeout: float, *, starttls: str | None = None
) -> socket.socket:
    """Return a connected plaintext socket, with the STARTTLS preamble done.

    Args:
        host: Address to connect to.
        port: TCP port.
        timeout: Timeout in seconds for the connection and each preamble step.
        starttls: One of `starttls.PROTOCOLS` to negotiate before returning,
            or `None` for a bare connection.

    Raises:
        OSError: If the host cannot be reached, or the server refuses STARTTLS
            (`starttls.StartTLSError`, an `OSError` subclass).
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if starttls:
            starttls_negotiation.negotiate(sock, starttls)
    except BaseException:
        sock.close()
        raise
    return sock


def open_tls_stream(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    *,
    server_hostname: str | None,
    starttls: str | None = None,
) -> ssl.SSLSocket:
    """Return a TLS socket handshaken with `context` over a fresh stream.

    The plaintext socket is closed if the handshake fails, so a failed attempt
    never leaks a connection.
    """
    sock = open_stream(host, port, timeout, starttls=starttls)
    try:
        return context.wrap_socket(sock, server_hostname=server_hostname)
    except BaseException:
        sock.close()
        raise
