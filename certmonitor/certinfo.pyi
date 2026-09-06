# type: ignore
"""Stub file for certinfo Rust module to help with type checking."""

from typing import Any

def parse_public_key_info(der_bytes: bytes) -> dict[str, Any]:
    """Parse public key information from DER bytes."""
    ...

def extract_public_key_der(der_bytes: bytes) -> bytes:
    """Extract public key in DER format."""
    ...

def extract_public_key_pem(der_bytes: bytes) -> str:
    """Extract public key in PEM format."""
    ...

def analyze_chain(chain_ders: list[bytes]) -> dict[str, Any]:
    """Analyze a certificate chain (list of DER certs)."""
    ...

def pq_algorithms() -> list[dict[str, Any]]:
    """Return the post-quantum algorithm registry as
    [{"dotted": str, "name": str, "composite": bool}, ...]."""
    ...

def probe_tls_handshake(
    host: str,
    port: int = 443,
    timeout_ms: int = 10000,
    server_name: str | None = None,
    starttls: str | None = None,
    proxy: tuple[str, str, int, str | None, str | None] | None = None,
) -> dict[str, Any]:
    """Probe a TLS 1.3 server's key-exchange group. `host` is the address to
    connect to and `server_name` the SNI to offer (defaults to `host`; IP
    literals never send SNI). `starttls` names a service whose plaintext
    preamble runs first (smtp, imap, pop3, ftp, postgres, ldap). `proxy` is a
    `ProxyConfig` tuple (scheme, host, port, username, password) to tunnel
    through an HTTP CONNECT or SOCKS5 proxy. Returns a dict in every terminal
    state:
      - {"result": "group", "id", "name", "kind", "is_pq", "protocol",
         "via_hello_retry_request"}
      - {"result": "n/a", "reason", "protocol"}
      - {"result": "error", "error", "message"}
    """
    ...
