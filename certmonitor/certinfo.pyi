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

    Returns `response_status`, `responder_name` (with `responder_name_der`) or
    `responder_key_hash`,
    `produced_at` (unix seconds), `signature_algorithm`,
    `signature_algorithm_params` (the raw DER parameters, or `None` when
    absent or NULL, e.g. for RSASSA-PSS), `signature`,
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
    """A DER CRL's `issuer` (and its raw DER as `issuer_der`), `this_update`,
    `next_update` (unix seconds or None), `signature_algorithm`,
    `signature_algorithm_params` (the raw DER parameters, or `None` when
    absent or NULL, e.g. for RSASSA-PSS),
    `revoked_count`, and the signed bytes (`tbs_cert_list`) with their
    `signature`. Also reports `delta_crl_indicator` (`True` when the CRL
    lists only changes since a base CRL) and `issuing_distribution_point`,
    a dict of the bool keys `only_contains_user_certs`,
    `only_contains_ca_certs`, `only_some_reasons`, `indirect_crl`, and
    `only_contains_attribute_certs`, the list `distribution_point_uris`
    (every `uniformResourceIdentifier` the distribution point names), and
    the bool `names_other_locations` (true when the distribution point
    names something that is not a URI, such as a directory name), or
    `None` when the CRL carries no issuing distribution point.
    """
    ...

def crl_lookup(der_data: bytes, serial_number: bytes) -> dict[str, Any] | None:
    """The CRL entry for `serial_number` (raw INTEGER bytes, leading zeros
    ignored): `revocation_time` and `revocation_reason`, or `None` when the
    serial is not listed.
    """
    ...

def signature_hash(algorithm: str) -> str | None:
    """The `hashlib` name (`sha1`, `sha256`, `sha384`, `sha512`) implied by a
    signature algorithm OID in dotted form, or `None` when CertMonitor cannot
    verify that algorithm (RSA PKCS#1 v1.5 and ECDSA are supported).
    """
    ...

def verify_signature(
    algorithm: str, digest: bytes, signature: bytes, spki_der: bytes
) -> bool:
    """Verify `signature` over `digest` with the public key in `spki_der`
    (a DER SubjectPublicKeyInfo). `digest` must already be hashed with the
    algorithm `signature_hash(algorithm)` names. Returns `False` for a
    signature that does not verify; raises `ValueError` when the algorithm,
    curve, or key is unsupported or malformed.
    """
    ...

def parse_spki(spki_der: bytes) -> dict[str, Any]:
    """Parse a bare DER SubjectPublicKeyInfo into `algorithm`, `size`,
    `curve` (the same three keys `parse_public_key_info` reports for a whole
    certificate) and `key_bits`, the raw `subjectPublicKey` bits. Raises
    `ValueError` when the SubjectPublicKeyInfo does not parse.
    """
    ...

def eddsa_verify(curve: str, public_key: bytes, r: bytes, s: bytes, k: bytes) -> bool:
    """Verify a PureEdDSA signature (RFC 8032 §5.1.7, §5.2.7). `curve` is
    `"Ed25519"` or `"Ed448"`, `public_key` the raw `subjectPublicKey` bits,
    `r` and `s` the two halves of the signature, and `k` the challenge hash
    `H(R || A || M)`, which the caller computes so the hashing stays in
    Python. Returns `False` for a signature that is simply wrong; raises
    `ValueError` for an unknown curve name, for a key, signature half, or
    challenge of the wrong length, or for a public key that does not decode
    to a point on the curve.
    """
    ...

def certificate_signature_parts(der_data: bytes) -> dict[str, Any]:
    """The pieces needed to verify a certificate's own signature and to use it
    as a signer: `tbs`, `signature`, `signature_algorithm`,
    `signature_algorithm_params` (the raw DER parameters, or `None` when
    absent or NULL, e.g. for RSASSA-PSS), `spki`, `key_bits`,
    `subject`, `subject_der`, `issuer_der`, `not_before`, `not_after` (unix
    seconds), and `extended_key_usage` (OIDs in dotted form).
    """
    ...

def rsa_pss_encoded_message(signature: bytes, spki_der: bytes) -> tuple[bytes, int]:
    """The RSASSA-PSS encoded message `EM` and the modulus's bit length.

    `signature^e mod n` (RFC 8017 §5.2.2 RSAVP1) converted with I2OSP to
    `emLen = ceil((modBits - 1) / 8)` octets, per RFC 8017 §8.1.2 step 2.c,
    together with `modBits` so the caller can derive `emBits`. `spki_der`
    is a DER SubjectPublicKeyInfo naming an RSA key. No padding scheme is
    applied; RSASSA-PSS padding is checked in Python, using this primitive,
    while PKCS#1 v1.5 signatures go through `verify_signature`. Raises
    `ValueError` when the key is not RSA or is outside the supported
    bounds, when `signature` is not exactly `ceil(modBits / 8)` bytes long,
    when the signature integer is not less than the modulus, or when the
    recovered value needs more than `modBits - 1` bits.
    """
    ...

def rsa_pss_parameters(params_der: bytes | None) -> dict[str, Any]:
    """Parse `RSASSA-PSS-params` (RFC 4055 §3.1) into `hash` and `mgf_hash`
    (`hashlib` names), `salt_length` (int), and `trailer_field` (int).
    `None` means the AlgorithmIdentifier carried no parameters, which
    yields the RFC 4055 defaults: `sha1` for both hashes, a 20-byte salt,
    and trailer field 1. Raises `ValueError` when the mask generation
    function is not MGF1 (RFC 4055 §A.2.3), when a named hash is not one
    of SHA-1, SHA-256, SHA-384, or SHA-512, or when the trailer field is
    not 1 (the only value RFC 4055 defines).
    """
    ...
