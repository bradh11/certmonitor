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

def parse_ocsp_response(der_data: bytes) -> dict[str, Any]:
    """Parse a DER OCSP response (RFC 6960).

    Returns `response_status`, `responder_name` or `responder_key_hash`,
    `produced_at` (unix seconds), `signature_algorithm`, `signature`,
    `tbs_response_data` (the signed bytes), `certs` (attached responder
    certificates as DER), and `responses`: one dict per certificate with
    `cert_id`, `status` (good, revoked, unknown), `this_update`,
    `next_update`, `revocation_time`, and `revocation_reason`.
    Raises `ValueError` on malformed input.
    """
    ...

def ocsp_cert_id_inputs(leaf_der: bytes, issuer_der: bytes) -> dict[str, bytes] | None:
    """The inputs an OCSP CertID is built from: `serial_number` (raw INTEGER
    bytes), `issuer_name` (DER of the leaf's issuer name), and `issuer_key`
    (the issuer's public key bits). `None` when `issuer_der` did not issue
    `leaf_der`.
    """
    ...

def crl_info(der_data: bytes) -> dict[str, Any]:
    """A DER CRL's `issuer`, `this_update`, `next_update` (unix seconds or
    None), `signature_algorithm`, `revoked_count`, and the signed bytes
    (`tbs_cert_list`) with their `signature`.
    """
    ...

def crl_lookup(der_data: bytes, serial_number: bytes) -> dict[str, Any] | None:
    """The CRL entry for `serial_number` (raw INTEGER bytes, leading zeros
    ignored): `revocation_time` and `revocation_reason`, or `None` when the
    serial is not listed.
    """
    ...
