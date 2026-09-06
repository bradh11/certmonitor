# protocol_handlers/http.py

"""A small HTTP/1.1 client for the few fetches CertMonitor makes.

Revocation data (CRLs, OCSP responses, issuer certificates) is served over
plain HTTP by design. This client speaks just enough HTTP/1.1 to fetch it:
one request per connection, `Content-Length` or chunked bodies, a bounded
body size, and a handful of redirects. It opens its sockets through
`open_stream` so the monitor's timeout and proxy apply to these fetches
exactly as they do to every other connection.
"""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urljoin, urlsplit

from .connection import open_stream, open_tls_stream
from .proxy import ProxyConfig

DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_HEADER_LIMIT = 64 * 1024
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class HTTPError(OSError):
    """The server answered with an unexpected status, or the reply was malformed."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def fetch(
    url: str,
    *,
    timeout: float,
    proxy: ProxyConfig | None = None,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
    accept: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = 3,
    tls_context: ssl.SSLContext | None = None,
) -> bytes:
    """Fetch `url` and return the response body.

    Args:
        url: An `http://` or `https://` URL.
        timeout: Timeout in seconds for the connection and each read.
        proxy: Tunnel to reach the server through, or `None`.
        method: `GET` or `POST`.
        body: Request body for `POST`.
        content_type: `Content-Type` of `body`.
        accept: `Accept` header value, if the server should be told.
        max_bytes: Largest body accepted; a longer one raises `HTTPError`.
        max_redirects: Redirects followed before giving up.
        tls_context: Context for `https` URLs; defaults to the interpreter's
            verifying defaults.

    Raises:
        HTTPError: On a non-2xx status, a malformed reply, or an oversized body.
        OSError: If the server cannot be reached.
        ValueError: If the URL is not `http` or `https`.
    """
    for _ in range(max_redirects + 1):
        status, headers, payload = _request(
            url,
            timeout,
            proxy,
            method,
            body,
            content_type,
            accept,
            max_bytes,
            tls_context,
        )
        if 200 <= status < 300:
            return payload
        if status in _REDIRECT_STATUSES and headers.get("location"):
            url = urljoin(url, headers["location"])
            if status == 303 or (status in (301, 302) and method == "POST"):
                method, body, content_type = "GET", None, None
            continue
        raise HTTPError(f"HTTP {status} from {url}", status)
    raise HTTPError(f"too many redirects fetching {url}")


def _request(
    url: str,
    timeout: float,
    proxy: ProxyConfig | None,
    method: str,
    body: bytes | None,
    content_type: str | None,
    accept: str | None,
    max_bytes: int,
    tls_context: ssl.SSLContext | None,
) -> tuple[int, dict[str, str], bytes]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(
            f"cannot fetch {url!r}: only http and https URLs are supported"
        )
    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    host_header = f"[{host}]" if ":" in host else host
    if parts.port:
        host_header += f":{parts.port}"

    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: certmonitor",
        "Connection: close",
    ]
    if accept:
        lines.append(f"Accept: {accept}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
        if content_type:
            lines.append(f"Content-Type: {content_type}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + (body or b"")

    sock: socket.socket
    if scheme == "https":
        sock = open_tls_stream(
            host,
            port,
            timeout,
            tls_context or ssl.create_default_context(),
            server_hostname=host,
            proxy=proxy,
        )
    else:
        sock = open_stream(host, port, timeout, proxy=proxy)
    with sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        return _read_response(sock, max_bytes)


def _read_response(
    sock: socket.socket, max_bytes: int
) -> tuple[int, dict[str, str], bytes]:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise HTTPError("server closed the connection before sending headers")
        buffer += chunk
        if len(buffer) > _HEADER_LIMIT:
            raise HTTPError("response headers too long")
    head, _, rest = bytes(buffer).partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("latin-1").split("\r\n")
    words = status_line.split(" ", 2)
    if len(words) < 2 or not words[0].startswith("HTTP/") or not words[1].isdigit():
        raise HTTPError(f"malformed status line {status_line!r}")
    status = int(words[1])
    headers: dict[str, str] = {}
    for line in header_lines:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    if "chunked" in headers.get("transfer-encoding", "").lower():
        payload = _read_chunked(sock, bytearray(rest), max_bytes)
    elif "content-length" in headers:
        length = int(headers["content-length"])
        if length > max_bytes:
            raise HTTPError(
                f"response body of {length} bytes exceeds the {max_bytes} byte limit"
            )
        payload = _read_exactly(sock, bytearray(rest), length)
    else:
        payload = _read_to_close(sock, bytearray(rest), max_bytes)
    return status, headers, payload


def _fill(sock: socket.socket, buffer: bytearray, needed: int, max_bytes: int) -> None:
    """Grow `buffer` until it holds `needed` bytes or the server hangs up."""
    while len(buffer) < needed:
        if len(buffer) > max_bytes:
            raise HTTPError(f"response body exceeds the {max_bytes} byte limit")
        chunk = sock.recv(65536)
        if not chunk:
            raise HTTPError("server closed the connection mid-body")
        buffer += chunk


def _read_exactly(sock: socket.socket, buffer: bytearray, length: int) -> bytes:
    _fill(sock, buffer, length, length)
    return bytes(buffer[:length])


def _read_to_close(sock: socket.socket, buffer: bytearray, max_bytes: int) -> bytes:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(buffer)
        buffer += chunk
        if len(buffer) > max_bytes:
            raise HTTPError(f"response body exceeds the {max_bytes} byte limit")


def _read_chunked(sock: socket.socket, buffer: bytearray, max_bytes: int) -> bytes:
    payload = bytearray()
    while True:
        while b"\r\n" not in buffer:
            _fill(sock, buffer, len(buffer) + 1, max_bytes)
        size_line, _, remainder = bytes(buffer).partition(b"\r\n")
        buffer = bytearray(remainder)
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError as exc:
            raise HTTPError(f"malformed chunk size {size_line!r}") from exc
        if size == 0:
            return bytes(payload)
        _fill(sock, buffer, size + 2, max_bytes)
        payload += buffer[:size]
        if len(payload) > max_bytes:
            raise HTTPError(f"response body exceeds the {max_bytes} byte limit")
        del buffer[: size + 2]
