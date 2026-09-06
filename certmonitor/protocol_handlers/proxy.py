"""Outbound proxies: HTTP CONNECT tunnels and SOCKS5, standard library only.

`open_connection()` is the one place CertMonitor opens a TCP connection. With
no proxy it is `socket.create_connection()`; with one it connects to the
proxy, negotiates a tunnel to the target, and returns the socket ready for a
TLS handshake or a STARTTLS preamble, exactly as a direct connection would be.
"""

from __future__ import annotations

import base64
import ipaddress
import socket
import struct
from typing import NamedTuple
from urllib.parse import unquote, urlsplit

SCHEMES = ("http", "socks5", "socks5h")
_LINE_LIMIT = 4096
_SOCKS5_ERRORS = {
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class ProxyError(OSError):
    """The proxy refused the tunnel, rejected the credentials, or misbehaved."""


class ProxyConfig(NamedTuple):
    """A parsed proxy URL. `scheme` is `"http"` or `"socks5"`."""

    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def redacted(self) -> str:
        """The proxy URL without its password, safe for results and logs."""
        auth = f"{self.username}@" if self.username else ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{auth}{host}:{self.port}"


def parse_proxy(url: str) -> ProxyConfig:
    """Parse `http://[user:pass@]host:port` or `socks5://[user:pass@]host:port`.

    `socks5h://` is accepted as a synonym: the proxy always resolves the target
    name, so no DNS query leaves the scanning host either way.

    Raises:
        ValueError: If the scheme is unsupported or the host or port is missing.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in SCHEMES:
        raise ValueError(
            f"unsupported proxy scheme {parts.scheme!r}; use http:// or socks5://"
        )
    if not parts.hostname:
        raise ValueError(f"proxy URL {url!r} has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"proxy URL {url!r} has an invalid port") from exc
    if port is None:
        port = 1080 if scheme.startswith("socks") else 3128
    username = unquote(parts.username) if parts.username else None
    password = unquote(parts.password) if parts.password else None
    return ProxyConfig(
        "socks5" if scheme.startswith("socks") else "http",
        parts.hostname,
        port,
        username,
        password,
    )


def open_connection(
    host: str, port: int, timeout: float, proxy: ProxyConfig | None = None
) -> socket.socket:
    """Return a connected socket to `host:port`, tunnelled through `proxy` when given."""
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        if proxy.scheme == "http":
            _http_connect(sock, host, port, proxy)
        else:
            _socks5_connect(sock, host, port, proxy)
    except ProxyError:
        sock.close()
        raise
    except OSError as exc:
        sock.close()
        raise ProxyError(
            f"proxy {proxy.redacted} failed during negotiation: {exc}"
        ) from exc
    except BaseException:
        sock.close()
        raise
    return sock


# --- HTTP CONNECT ---------------------------------------------------------------


def _read_line(sock: socket.socket) -> bytes:
    line = bytearray()
    while not line.endswith(b"\n"):
        byte = sock.recv(1)
        if not byte:
            raise ProxyError("proxy closed the connection during CONNECT")
        line += byte
        if len(line) > _LINE_LIMIT:
            raise ProxyError("proxy reply line too long")
    return bytes(line).rstrip(b"\r\n")


def _http_connect(
    sock: socket.socket, host: str, port: int, proxy: ProxyConfig
) -> None:
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if proxy.username is not None:
        token = base64.b64encode(
            f"{proxy.username}:{proxy.password or ''}".encode()
        ).decode()
        request += f"Proxy-Authorization: Basic {token}\r\n"
    sock.sendall((request + "\r\n").encode())
    status = _read_line(sock).decode("latin-1")
    parts = status.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ProxyError(f"proxy sent an invalid CONNECT reply: {status!r}")
    while _read_line(sock):  # drain headers up to the blank line
        pass
    code = int(parts[1])
    if code == 407:
        raise ProxyError("proxy requires authentication (407)")
    if not 200 <= code < 300:
        raise ProxyError(f"proxy refused CONNECT to {target}: {status}")


# --- SOCKS5 (RFC 1928, RFC 1929) ---------------------------------------------------


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProxyError("proxy closed the connection during SOCKS5 negotiation")
        data += chunk
    return bytes(data)


def _socks5_connect(
    sock: socket.socket, host: str, port: int, proxy: ProxyConfig
) -> None:
    methods = b"\x00\x02" if proxy.username is not None else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2)
    if version != 5:
        raise ProxyError(f"proxy is not SOCKS5 (version byte {version})")
    if method == 0xFF:
        raise ProxyError(
            "proxy accepts none of the offered SOCKS5 authentication methods"
        )
    if method == 2:
        username = (proxy.username or "").encode()
        password = (proxy.password or "").encode()
        sock.sendall(
            b"\x01"
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        _, status = _recv_exact(sock, 2)
        if status != 0:
            raise ProxyError("proxy rejected the SOCKS5 username or password")
    elif method != 0:
        raise ProxyError(f"proxy chose an unsupported SOCKS5 method ({method})")

    try:
        address = ipaddress.ip_address(host)
        if address.version == 4:
            destination = b"\x01" + address.packed
        else:
            destination = b"\x04" + address.packed
    except ValueError:
        try:
            name = host.encode("idna")
        except UnicodeError as exc:
            raise ProxyError(
                f"target host name {host!r} is not a valid IDNA name"
            ) from exc
        if len(name) > 255:
            raise ProxyError("target host name too long for SOCKS5")
        destination = b"\x03" + bytes([len(name)]) + name
    sock.sendall(b"\x05\x01\x00" + destination + struct.pack("!H", port))
    version, reply, _, address_type = _recv_exact(sock, 4)
    if version != 5:
        raise ProxyError("proxy sent an invalid SOCKS5 reply")
    if address_type == 1:
        _recv_exact(sock, 4 + 2)
    elif address_type == 4:
        _recv_exact(sock, 16 + 2)
    elif address_type == 3:
        (length,) = _recv_exact(sock, 1)
        _recv_exact(sock, length + 2)
    else:
        raise ProxyError("proxy sent an invalid SOCKS5 address type")
    if reply != 0:
        raise ProxyError(
            f"proxy refused the SOCKS5 connection to {host}:{port}: {_SOCKS5_ERRORS.get(reply, f'reply code {reply}')}"
        )
