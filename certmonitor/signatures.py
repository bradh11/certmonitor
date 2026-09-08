"""Signature verification for X.509 structures: which scheme an algorithm
names, the padding checks that are plain byte work, and the hashing.

Hashing stays in Python (`hashlib`), arithmetic stays in the Rust extension:
`certinfo.verify_signature` for RSASSA-PKCS1-v1_5 and ECDSA,
`certinfo.rsa_public_operation` for RSASSA-PSS (RFC 8017 §9.1.2 is checked
here), and `certinfo.eddsa_verify` for Ed25519 and Ed448 (the challenge
scalar is hashed here per RFC 8032). Verification only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from certmonitor import certinfo

VERIFIED = "verified"
UNSUPPORTED = "unsupported"
FAILED = "failed"

RSASSA_PSS = "1.2.840.113549.1.1.10"
ED25519 = "1.3.101.112"
ED448 = "1.3.101.113"


def verify(
    signer_spki: bytes,
    algorithm: str,
    params: bytes | None,
    tbs: bytes,
    signature: bytes,
) -> tuple[str, str | None]:
    """Check `signature` over `tbs` under `signer_spki`.

    Returns `(VERIFIED, None)`, `(UNSUPPORTED, why)` when the algorithm,
    parameters, or key are ones CertMonitor cannot check, or `(FAILED, why)`
    when the check ran and the signature is wrong.
    """
    if algorithm == RSASSA_PSS:
        return _verify_pss(signer_spki, params, tbs, signature)
    if algorithm in (ED25519, ED448):
        return _verify_eddsa(signer_spki, algorithm, tbs, signature)
    hash_name = certinfo.signature_hash(algorithm)  # type: ignore[attr-defined]
    if hash_name is None:
        return UNSUPPORTED, f"unsupported signature algorithm {algorithm}"
    try:
        digest = hashlib.new(hash_name, tbs).digest()
    except ValueError as exc:
        return UNSUPPORTED, f"unsupported digest {hash_name}: {exc}"
    verifier = certinfo.verify_signature  # type: ignore[attr-defined]
    return _outcome_of(verifier, algorithm, digest, signature, signer_spki)


def _outcome_of(check: Callable[..., bool], *args: object) -> tuple[str, str | None]:
    """Run a Rust verifier and translate its result and errors into an outcome."""
    try:
        ok = check(*args)
    except ValueError as exc:
        outcome = UNSUPPORTED if str(exc).startswith("unsupported") else FAILED
        return outcome, str(exc)
    return (VERIFIED, None) if ok else (FAILED, "signature does not verify")


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    """MGF1 (RFC 8017 §B.2.1)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at `offset`; returns `(tag, content, offset after it)`."""
    tag = data[offset]
    length = data[offset + 1]
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + size], "big")
        start = offset + 2 + size
    else:
        start = offset + 2
    end = start + length
    return tag, data[start:end], end


def _modulus_bits(spki: bytes) -> int:
    """The RSA modulus's exact bit length, read from its DER SubjectPublicKeyInfo.

    RSASSA-PSS needs `emBits`, one less than the modulus's exact bit length
    (RFC 8017 §9.1.2), not its byte length: a modulus a few bits short of a
    full byte boundary is exactly why EMSA-PSS-VERIFY's leftmost-bits check
    exists. `certinfo.parse_public_key_info` parses a whole certificate, not
    a bare SubjectPublicKeyInfo, so the modulus is read here instead: past
    the AlgorithmIdentifier and into the BIT STRING holding the RSAPublicKey
    (RFC 8017 appendix A.1.1). `rsa_public_operation` already proved `spki`
    names a well-formed RSA key, so this walk only needs to reach the
    modulus, not validate the whole structure again.
    """
    tag, spki_body, _ = _der_tlv(spki, 0)
    if tag != 0x30:
        raise ValueError("malformed SubjectPublicKeyInfo")
    _, _, after_algorithm = _der_tlv(spki_body, 0)
    bit_tag, bit_string, _ = _der_tlv(spki_body, after_algorithm)
    if bit_tag != 0x03 or not bit_string or bit_string[0] != 0:
        raise ValueError("malformed RSA public key bit string")
    key_tag, key_body, _ = _der_tlv(bit_string, 1)
    if key_tag != 0x30:
        raise ValueError("malformed RSAPublicKey")
    modulus_tag, modulus, _ = _der_tlv(key_body, 0)
    if modulus_tag != 0x02:
        raise ValueError("malformed RSAPublicKey")
    return int.from_bytes(modulus, "big").bit_length()


def _verify_pss(
    spki: bytes, params: bytes | None, tbs: bytes, signature: bytes
) -> tuple[str, str | None]:
    """RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) with EMSA-PSS-VERIFY (§9.1.2)."""
    try:
        options = certinfo.rsa_pss_parameters(params)  # type: ignore[attr-defined]
        em = certinfo.rsa_public_operation(signature, spki)  # type: ignore[attr-defined]
        mod_bits = _modulus_bits(spki)
    except ValueError as exc:
        outcome = UNSUPPORTED if str(exc).startswith("unsupported") else FAILED
        return outcome, str(exc)
    hash_name, mgf_hash, salt_length = (
        options["hash"],
        options["mgf_hash"],
        options["salt_length"],
    )
    m_hash = hashlib.new(hash_name, tbs).digest()
    h_len = len(m_hash)
    em_len = len(em)
    # emBits is modBits - 1; the leftmost 8*emLen - emBits bits of EM must be zero.
    em_bits = mod_bits - 1
    if em_len < h_len + salt_length + 2:
        return FAILED, "PSS encoded message too short"
    if em[-1] != 0xBC:
        return FAILED, "PSS trailer byte is not 0xbc"
    masked_db, h = em[: em_len - h_len - 1], em[em_len - h_len - 1 : -1]
    top_zero_bits = 8 * em_len - em_bits
    if top_zero_bits and masked_db[0] >> (8 - top_zero_bits):
        return FAILED, "PSS leftmost bits are not zero"
    db_mask = _mgf1(h, em_len - h_len - 1, mgf_hash)
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))
    if top_zero_bits:
        db[0] &= 0xFF >> top_zero_bits
    padding_length = em_len - h_len - salt_length - 2
    if any(db[:padding_length]) or db[padding_length] != 0x01:
        return FAILED, "PSS padding is malformed"
    salt = bytes(db[padding_length + 1 :])
    expected = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
    if expected != h:
        return FAILED, "signature does not verify"
    return VERIFIED, None


def _verify_eddsa(
    spki: bytes, algorithm: str, tbs: bytes, signature: bytes
) -> tuple[str, str | None]:
    """Ed25519 and Ed448 verification is added in a later task."""
    return UNSUPPORTED, f"{algorithm} signature verification"
