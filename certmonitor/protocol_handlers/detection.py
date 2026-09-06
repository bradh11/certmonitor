# protocol_handlers/detection.py

"""Work out which handler a port needs before any certificate is fetched.

Detection peeks at the first bytes a server sends. An SSH banner or a TLS
record settles it at once, and a server that sends nothing is assumed to be
waiting for a TLS ClientHello. A plaintext greeting means a STARTTLS service,
so detection asks `starttls.discover` to name it rather than reporting an
error. `CertMonitor.detect_protocol()` wraps this in the result envelope.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import NamedTuple

from . import starttls as starttls_negotiation
from .connection import open_stream

Connector = Callable[[str, int, float], socket.socket]
"""Opens a plaintext socket to `(host, port, timeout)`; proxies plug in here."""

_TLS_FIRST_BYTES = (22, 128, 160)


class Detected(NamedTuple):
    """What a port speaks: the handler protocol and any preamble it needs."""

    protocol: str
    """`"ssl"` or `"ssh"`."""
    starttls: str | None
    """STARTTLS protocol the SSL handler must negotiate first, if any."""


class ProtocolDetectionError(OSError):
    """The port answered, but with something CertMonitor cannot name."""


def detect(
    host: str, port: int, timeout: float, *, connect: Connector = open_stream
) -> Detected:
    """Name the protocol on `host:port` from its first bytes.

    Args:
        host: Address to connect to.
        port: TCP port.
        timeout: Timeout in seconds for the connection and for discovery.
        connect: Opens the plaintext socket; the default connects directly.

    Raises:
        ProtocolDetectionError: If the server greeted in plaintext and no
            STARTTLS service could be named.
        OSError: If the host cannot be reached.
    """
    with connect(host, port, timeout) as sock:
        sock.setblocking(False)
        try:
            data = sock.recv(4, socket.MSG_PEEK)
        except OSError:
            # Nothing waiting: a TLS server speaks only after the ClientHello.
            return Detected("ssl", None)
        finally:
            sock.setblocking(True)
    if data.startswith(b"SSH-"):
        return Detected("ssh", None)
    if data and data[0] in _TLS_FIRST_BYTES:
        return Detected("ssl", None)
    # A plaintext greeting: name the service so its STARTTLS preamble can run
    # instead of a doomed handshake.
    try:
        discovered = starttls_negotiation.discover(host, port, timeout, connect=connect)
    except OSError:
        discovered = None
    if discovered == "ssh":
        return Detected("ssh", None)
    if discovered is not None:
        return Detected("ssl", discovered)
    raise ProtocolDetectionError(
        f"Unable to determine protocol. First bytes: {data.hex()}"
    )
