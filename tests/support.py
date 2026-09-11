"""DER helpers the signature tests share.

RSASSA-PSS carries its hash, mask generation function, and salt length in
`RSASSA-PSS-params` (RFC 4055 §3.1) rather than in the algorithm OID, so
every PSS test has to build those parameters before it can ask
`certmonitor.signatures.verify` anything. `pss_params` is that encoder.
"""

from __future__ import annotations

HASH_OIDS = {
    "sha1": bytes.fromhex("2b0e03021a"),
    "sha256": bytes.fromhex("608648016503040201"),
    "sha384": bytes.fromhex("608648016503040202"),
    "sha512": bytes.fromhex("608648016503040203"),
}
OID_MGF1 = bytes.fromhex("2a864886f70d010108")


def der(tag: int, content: bytes) -> bytes:
    """Encode one DER TLV, mirroring `revocation._der`."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    size = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content


def der_integer(value: int) -> bytes:
    """DER INTEGER encoding of a non-negative value."""
    length = max(1, (value.bit_length() + 7) // 8)
    content = value.to_bytes(length, "big")
    if content[0] & 0x80:
        # A leading 0x00 keeps the high bit from reading as a sign bit.
        content = b"\x00" + content
    return der(0x02, content)


def algorithm_identifier(oid: bytes) -> bytes:
    """`AlgorithmIdentifier { oid, NULL }`, the shape RFC 4055 §2.1 uses."""
    return der(0x30, der(0x06, oid) + der(0x05, b""))


def pss_params(hash_name: str, mgf_hash_name: str, salt_length: int) -> bytes:
    """`RSASSA-PSS-params` (RFC 4055 §3.1) for MGF1 with an explicit salt length.

    Hash names are `hashlib` names: `sha1`, `sha256`, `sha384`, or `sha512`.
    `trailerField` is left at its default, the only value RFC 4055 defines.
    """
    hash_id = algorithm_identifier(HASH_OIDS[hash_name])
    mgf_id = der(
        0x30, der(0x06, OID_MGF1) + algorithm_identifier(HASH_OIDS[mgf_hash_name])
    )
    return der(
        0x30,
        der(0xA0, hash_id) + der(0xA1, mgf_id) + der(0xA2, der_integer(salt_length)),
    )


OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
OID_DATA = bytes.fromhex("2a864886f70d010701")


def pkcs7_certs_only(certs: list[bytes]) -> bytes:
    """A DER certs-only PKCS#7 message (CMS SignedData, RFC 5652 §5.1) carrying `certs`.

    The shape `openssl crl2pkcs7 -nocrl -certfile` produces: version 1, no
    digest algorithms, id-data with no content, the certificates, no CRLs,
    and no signers.
    """
    signed_data = (
        der(0x02, b"\x01")
        + der(0x31, b"")
        + der(0x30, der(0x06, OID_DATA))
        + der(0xA0, b"".join(certs))
        + der(0x31, b"")
    )
    return der(0x30, der(0x06, OID_SIGNED_DATA) + der(0xA0, der(0x30, signed_data)))
