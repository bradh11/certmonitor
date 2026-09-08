"""Application-protocol preambles that upgrade a plain socket to TLS.

Some services start in plaintext and switch to TLS only after a short
exchange (STARTTLS). Each function here performs that exchange on an
already-connected socket and returns once the server has agreed to start
TLS, leaving the socket ready for `SSLContext.wrap_socket()`. Nothing here
imports beyond the standard library.
"""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Callable

PROTOCOLS = ("smtp", "imap", "pop3", "ftp", "postgres", "ldap")

LDAP_STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"
_POSTGRES_SSL_REQUEST_CODE = 80877103
_LINE_LIMIT = 4096
_REPLY_LINE_LIMIT = 64


class StartTLSError(OSError):
    """The server did not agree to start TLS, or the preamble was malformed."""


def negotiate(
    sock: socket.socket,
    protocol: str,
    *,
    client_name: str = "certmonitor",
    timeout: float | None = None,
) -> None:
    """Run the STARTTLS preamble for `protocol` on `sock`.

    Args:
        sock: A connected plaintext socket.
        protocol: One of `PROTOCOLS`.
        client_name: Name announced to servers that ask for one (SMTP EHLO).
        timeout: Budget in seconds for the whole preamble, every read and
            write included, so a server that trickles bytes cannot stretch
            it. Defaults to the socket's own timeout; `None` on a blocking
            socket means no deadline. The socket's timeout is restored
            afterwards.

    Raises:
        ValueError: If `protocol` is not supported.
        StartTLSError: If the server refuses or answers unexpectedly.
        TimeoutError: If the budget runs out before the server agrees.
    """
    handler = _HANDLERS.get(protocol)
    if handler is None:
        raise ValueError(
            f"unsupported STARTTLS protocol {protocol!r}; choose one of {', '.join(PROTOCOLS)}"
        )
    wire = _Wire(sock, sock.gettimeout() if timeout is None else timeout)
    try:
        handler(wire, client_name)
    except ConnectionError as exc:
        # A reset or broken pipe mid-preamble means the server hung up on us,
        # which callers should see the same way as an orderly close.
        raise StartTLSError(
            f"connection closed during STARTTLS negotiation: {exc}"
        ) from exc
    finally:
        wire.restore()


class _Wire:
    """A socket with one deadline for a whole exchange.

    Each read or write gets whatever time remains, so a server that sends a
    byte every so often cannot keep the exchange alive the way a per-call
    socket timeout, which restarts whenever a byte arrives, would let it.
    With no budget the socket is used as it is.
    """

    def __init__(self, sock: socket.socket, budget: float | None) -> None:
        self.sock = sock
        self.original_timeout = sock.gettimeout()
        self.deadline = None if budget is None else time.monotonic() + budget

    def arm(self) -> None:
        """Give the next socket call the time that is left, or give up."""
        if self.deadline is None:
            return
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("STARTTLS negotiation ran out of time")
        self.sock.settimeout(remaining)

    def recv(self, size: int) -> bytes:
        self.arm()
        return self.sock.recv(size)

    def sendall(self, data: bytes) -> None:
        self.arm()
        self.sock.sendall(data)

    def restore(self) -> None:
        """Put the socket's own timeout back for whatever comes next."""
        if self.deadline is not None:
            self.sock.settimeout(self.original_timeout)


# --- discovery ----------------------------------------------------------------


def _direct_connection(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def discover(
    host: str,
    port: int,
    timeout: float,
    *,
    client_name: str = "certmonitor",
    connect: Callable[[str, int, float], socket.socket] = _direct_connection,
) -> str | None:
    """Name the plaintext service on `host:port` so the right STARTTLS preamble can run.

    Nothing here looks at the port number, so services on non-standard ports are
    found just the same. A service that speaks first is named from its greeting:
    IMAP (`* OK`), POP3 (`+OK`), SSH (`SSH-`), and the `220` greeting shared by
    SMTP and FTP, which is settled by the greeting text or, failing that, by
    whether the server answers `EHLO` with `250`. A service that stays silent is
    asked, in turn, the PostgreSQL `SSLRequest` and the LDAP StartTLS request,
    and is named from the reply. The whole exchange is bounded by `timeout`.

    Args:
        host: Address to connect to.
        port: TCP port.
        timeout: Total time budget in seconds for discovery.
        client_name: Name announced in the `EHLO` used to tell SMTP from FTP.
        connect: Opens a plaintext socket to `(host, port, timeout)`; the default
            connects directly, and a proxy-aware opener routes discovery too.

    Returns:
        One of `PROTOCOLS`, `"ssh"` for an SSH banner, or `None` when the service
        could not be named.

    Raises:
        OSError: If the first connection to the host fails.
    """
    deadline = time.monotonic() + timeout
    with connect(host, port, timeout) as sock:
        greeting = _wait_for_greeting(_Wire(sock, _remaining(deadline) / 2))
        if greeting is not None:
            return _name_greeting(
                _Wire(sock, _remaining(deadline)), greeting, client_name
            )
        if _answers_ssl_request(_Wire(sock, _remaining(deadline) / 2)):
            return "postgres"
    try:
        with connect(host, port, _remaining(deadline)) as sock:
            if _answers_ldap_starttls(_Wire(sock, _remaining(deadline))):
                return "ldap"
    except OSError:
        return None
    return None


def _remaining(deadline: float) -> float:
    """Seconds left before `deadline`, never below a tiny floor so socket calls stay blocking."""
    return max(deadline - time.monotonic(), 0.01)


def _wait_for_greeting(wire: _Wire) -> list[str] | None:
    """Return the server's greeting lines, or `None` if it stays silent or hangs up."""
    try:
        lines = [_read_line(wire)]
        while lines[-1].startswith("220-"):
            lines.append(_read_line(wire))
    except OSError:
        return None
    return lines


def _name_greeting(wire: _Wire, lines: list[str], client_name: str) -> str | None:
    first = lines[0]
    if first.startswith("SSH-"):
        return "ssh"
    if first.startswith("* "):
        return "imap"
    if first.startswith("+OK"):
        return "pop3"
    if not first.startswith("220"):
        return None
    text = "\n".join(lines).upper()
    if "SMTP" in text:
        return "smtp"
    if "FTP" in text:
        return "ftp"
    # Both SMTP and FTP greet with 220; only SMTP answers EHLO with 250.
    try:
        wire.sendall(f"EHLO {client_name}\r\n".encode("ascii"))
        code, _ = _read_reply(wire)
    except OSError:
        return None
    return "smtp" if code == "250" else "ftp"


def _answers_ssl_request(wire: _Wire) -> bool:
    """Send the PostgreSQL `SSLRequest`; any of its one-byte answers names PostgreSQL."""
    try:
        wire.sendall(struct.pack("!ii", 8, _POSTGRES_SSL_REQUEST_CODE))
        reply = wire.recv(1)
    except OSError:
        return False
    return reply in (b"S", b"N", b"E")


def _answers_ldap_starttls(wire: _Wire) -> bool:
    """Send the LDAP StartTLS request; any LDAPMessage reply (a BER SEQUENCE) names LDAP."""
    try:
        wire.sendall(ldap_starttls_request())
        reply = wire.recv(1)
    except OSError:
        return False
    return reply == b"\x30"


# --- line-oriented protocols -------------------------------------------------


def _read_line(wire: _Wire) -> str:
    """Read one CRLF- or LF-terminated line, byte by byte so nothing past it is consumed."""
    line = bytearray()
    while not line.endswith(b"\n"):
        byte = wire.recv(1)
        if not byte:
            raise StartTLSError("connection closed during STARTTLS negotiation")
        line += byte
        if len(line) > _LINE_LIMIT:
            raise StartTLSError("STARTTLS reply line too long")
    return line.decode("utf-8", errors="replace").rstrip("\r\n")


def _read_reply(wire: _Wire) -> tuple[str, list[str]]:
    """Read an SMTP/FTP style reply; multiline replies use `NNN-` continuation lines."""
    lines: list[str] = []
    while True:
        line = _read_line(wire)
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            return line[:3], lines
        if len(lines) >= _REPLY_LINE_LIMIT:
            raise StartTLSError("STARTTLS reply has too many lines")


def _expect(wire: _Wire, code: str, what: str) -> list[str]:
    got, lines = _read_reply(wire)
    if got != code:
        raise StartTLSError(f"{what}: expected {code}, server said {lines[-1]!r}")
    return lines


def _smtp(wire: _Wire, client_name: str) -> None:
    _expect(wire, "220", "SMTP greeting")
    wire.sendall(f"EHLO {client_name}\r\n".encode())
    capabilities = _expect(wire, "250", "SMTP EHLO")
    if not any(line[4:].upper().startswith("STARTTLS") for line in capabilities):
        raise StartTLSError("SMTP server does not advertise STARTTLS")
    wire.sendall(b"STARTTLS\r\n")
    _expect(wire, "220", "SMTP STARTTLS")


def _ftp(wire: _Wire, client_name: str) -> None:
    _expect(wire, "220", "FTP greeting")
    wire.sendall(b"AUTH TLS\r\n")
    _expect(wire, "234", "FTP AUTH TLS")


def _imap(wire: _Wire, client_name: str) -> None:
    greeting = _read_line(wire)
    if not greeting.upper().startswith("* OK") and not greeting.upper().startswith(
        "* PREAUTH"
    ):
        raise StartTLSError(f"IMAP greeting: server said {greeting!r}")
    wire.sendall(b"a001 STARTTLS\r\n")
    # Untagged lines may precede the tagged reply, but not without end.
    for _ in range(_REPLY_LINE_LIMIT):
        line = _read_line(wire)
        if line.startswith("a001 "):
            if line[5:].upper().startswith("OK"):
                return
            raise StartTLSError(f"IMAP STARTTLS: server said {line!r}")
    raise StartTLSError("IMAP STARTTLS: too many untagged lines before the reply")


def _pop3(wire: _Wire, client_name: str) -> None:
    greeting = _read_line(wire)
    if not greeting.startswith("+OK"):
        raise StartTLSError(f"POP3 greeting: server said {greeting!r}")
    wire.sendall(b"STLS\r\n")
    reply = _read_line(wire)
    if not reply.startswith("+OK"):
        raise StartTLSError(f"POP3 STLS: server said {reply!r}")


# --- binary protocols --------------------------------------------------------


def _recv_exact(wire: _Wire, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = wire.recv(size - len(data))
        if not chunk:
            raise StartTLSError("connection closed during STARTTLS negotiation")
        data += chunk
    return bytes(data)


def _postgres(wire: _Wire, client_name: str) -> None:
    """PostgreSQL SSLRequest: 8 bytes out, one byte back ('S' agrees, 'N' declines)."""
    wire.sendall(struct.pack("!ii", 8, _POSTGRES_SSL_REQUEST_CODE))
    answer = _recv_exact(wire, 1)
    if answer == b"S":
        return
    if answer == b"N":
        raise StartTLSError("PostgreSQL server declined SSL")
    raise StartTLSError(f"PostgreSQL SSLRequest: unexpected reply {answer!r}")


def _ber(tag: int, content: bytes) -> bytes:
    """Encode one BER TLV with a definite length."""
    length = len(content)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        size = (length.bit_length() + 7) // 8
        header = bytes([tag, 0x80 | size]) + length.to_bytes(size, "big")
    return header + content


def _ber_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode one BER TLV at `offset`; return (tag, content, next offset)."""
    if offset + 2 > len(data):
        raise StartTLSError("LDAP reply truncated")
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first & 0x80:
        size = first & 0x7F
        if size == 0 or offset + size > len(data):
            raise StartTLSError("LDAP reply has an unsupported length encoding")
        length = int.from_bytes(data[offset : offset + size], "big")
        offset += size
    else:
        length = first
    if offset + length > len(data):
        raise StartTLSError("LDAP reply truncated")
    return tag, data[offset : offset + length], offset + length


def ldap_starttls_request(message_id: int = 1) -> bytes:
    """The LDAPMessage carrying an ExtendedRequest for the StartTLS OID (RFC 4511)."""
    extended_request = _ber(
        0x77, _ber(0x80, LDAP_STARTTLS_OID)
    )  # [APPLICATION 23], [0] requestName
    return _ber(0x30, _ber(0x02, bytes([message_id])) + extended_request)


def _ldap(wire: _Wire, client_name: str) -> None:
    wire.sendall(ldap_starttls_request())
    # Read the outer SEQUENCE header first so exactly one message is consumed.
    head = _recv_exact(wire, 2)
    if head[0] != 0x30:
        raise StartTLSError(
            f"LDAP reply: expected an LDAPMessage, got tag 0x{head[0]:02x}"
        )
    if head[1] & 0x80:
        size = head[1] & 0x7F
        if size == 0 or size > 4:
            raise StartTLSError("LDAP reply has an unsupported length encoding")
        length = int.from_bytes(_recv_exact(wire, size), "big")
    else:
        length = head[1]
    body = _recv_exact(wire, length)
    _, _message_id, offset = _ber_read(body, 0)
    op_tag, op, _ = _ber_read(body, offset)
    if op_tag != 0x78:  # [APPLICATION 24] ExtendedResponse
        raise StartTLSError(
            f"LDAP reply: expected an ExtendedResponse, got tag 0x{op_tag:02x}"
        )
    _, result_code, offset = _ber_read(op, 0)
    _, _matched_dn, offset = _ber_read(op, offset)
    _, diagnostic, _ = _ber_read(op, offset)
    code = int.from_bytes(result_code, "big") if result_code else -1
    if code != 0:
        detail = diagnostic.decode("utf-8", errors="replace") or f"resultCode {code}"
        raise StartTLSError(f"LDAP StartTLS refused: {detail}")


_HANDLERS: dict[str, Callable[[_Wire, str], None]] = {
    "smtp": _smtp,
    "imap": _imap,
    "pop3": _pop3,
    "ftp": _ftp,
    "postgres": _postgres,
    "ldap": _ldap,
}
