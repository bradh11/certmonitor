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
from collections.abc import Callable

PROTOCOLS = ("smtp", "imap", "pop3", "ftp", "postgres", "ldap")

LDAP_STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"
_POSTGRES_SSL_REQUEST_CODE = 80877103
_LINE_LIMIT = 4096


class StartTLSError(OSError):
    """The server did not agree to start TLS, or the preamble was malformed."""


def negotiate(
    sock: socket.socket, protocol: str, *, client_name: str = "certmonitor"
) -> None:
    """Run the STARTTLS preamble for `protocol` on `sock`.

    Args:
        sock: A connected plaintext socket.
        protocol: One of `PROTOCOLS`.
        client_name: Name announced to servers that ask for one (SMTP EHLO).

    Raises:
        ValueError: If `protocol` is not supported.
        StartTLSError: If the server refuses or answers unexpectedly.
    """
    handler = _HANDLERS.get(protocol)
    if handler is None:
        raise ValueError(
            f"unsupported STARTTLS protocol {protocol!r}; choose one of {', '.join(PROTOCOLS)}"
        )
    handler(sock, client_name)


# --- line-oriented protocols -------------------------------------------------


def _read_line(sock: socket.socket) -> str:
    """Read one CRLF- or LF-terminated line, byte by byte so nothing past it is consumed."""
    line = bytearray()
    while not line.endswith(b"\n"):
        byte = sock.recv(1)
        if not byte:
            raise StartTLSError("connection closed during STARTTLS negotiation")
        line += byte
        if len(line) > _LINE_LIMIT:
            raise StartTLSError("STARTTLS reply line too long")
    return line.decode("utf-8", errors="replace").rstrip("\r\n")


def _read_reply(sock: socket.socket) -> tuple[str, list[str]]:
    """Read an SMTP/FTP style reply; multiline replies use `NNN-` continuation lines."""
    lines: list[str] = []
    while True:
        line = _read_line(sock)
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            return line[:3], lines


def _expect(sock: socket.socket, code: str, what: str) -> list[str]:
    got, lines = _read_reply(sock)
    if got != code:
        raise StartTLSError(f"{what}: expected {code}, server said {lines[-1]!r}")
    return lines


def _smtp(sock: socket.socket, client_name: str) -> None:
    _expect(sock, "220", "SMTP greeting")
    sock.sendall(f"EHLO {client_name}\r\n".encode())
    capabilities = _expect(sock, "250", "SMTP EHLO")
    if not any(line[4:].upper().startswith("STARTTLS") for line in capabilities):
        raise StartTLSError("SMTP server does not advertise STARTTLS")
    sock.sendall(b"STARTTLS\r\n")
    _expect(sock, "220", "SMTP STARTTLS")


def _ftp(sock: socket.socket, client_name: str) -> None:
    _expect(sock, "220", "FTP greeting")
    sock.sendall(b"AUTH TLS\r\n")
    _expect(sock, "234", "FTP AUTH TLS")


def _imap(sock: socket.socket, client_name: str) -> None:
    greeting = _read_line(sock)
    if not greeting.upper().startswith("* OK") and not greeting.upper().startswith(
        "* PREAUTH"
    ):
        raise StartTLSError(f"IMAP greeting: server said {greeting!r}")
    sock.sendall(b"a001 STARTTLS\r\n")
    while True:
        line = _read_line(sock)
        if line.startswith("a001 "):
            if line[5:].upper().startswith("OK"):
                return
            raise StartTLSError(f"IMAP STARTTLS: server said {line!r}")


def _pop3(sock: socket.socket, client_name: str) -> None:
    greeting = _read_line(sock)
    if not greeting.startswith("+OK"):
        raise StartTLSError(f"POP3 greeting: server said {greeting!r}")
    sock.sendall(b"STLS\r\n")
    reply = _read_line(sock)
    if not reply.startswith("+OK"):
        raise StartTLSError(f"POP3 STLS: server said {reply!r}")


# --- binary protocols --------------------------------------------------------


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise StartTLSError("connection closed during STARTTLS negotiation")
        data += chunk
    return bytes(data)


def _postgres(sock: socket.socket, client_name: str) -> None:
    """PostgreSQL SSLRequest: 8 bytes out, one byte back ('S' agrees, 'N' declines)."""
    sock.sendall(struct.pack("!ii", 8, _POSTGRES_SSL_REQUEST_CODE))
    answer = _recv_exact(sock, 1)
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


def _ldap(sock: socket.socket, client_name: str) -> None:
    sock.sendall(ldap_starttls_request())
    # Read the outer SEQUENCE header first so exactly one message is consumed.
    head = _recv_exact(sock, 2)
    if head[0] != 0x30:
        raise StartTLSError(
            f"LDAP reply: expected an LDAPMessage, got tag 0x{head[0]:02x}"
        )
    if head[1] & 0x80:
        size = head[1] & 0x7F
        if size == 0 or size > 4:
            raise StartTLSError("LDAP reply has an unsupported length encoding")
        length = int.from_bytes(_recv_exact(sock, size), "big")
    else:
        length = head[1]
    body = _recv_exact(sock, length)
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


_HANDLERS: dict[str, Callable[[socket.socket, str], None]] = {
    "smtp": _smtp,
    "imap": _imap,
    "pop3": _pop3,
    "ftp": _ftp,
    "postgres": _postgres,
    "ldap": _ldap,
}
