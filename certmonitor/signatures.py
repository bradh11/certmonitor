"""Signature verification for X.509 structures: which scheme an algorithm
names, the padding checks that are plain byte work, and the hashing.

Hashing stays in Python (`hashlib`), arithmetic stays in the Rust extension:
`certinfo.verify_signature` for RSASSA-PKCS1-v1_5 and ECDSA,
`certinfo.rsa_pss_encoded_message` for RSASSA-PSS (RFC 8017 §9.1.2 is
checked here), and `certinfo.eddsa_verify` for Ed25519, whose challenge hash
(RFC 8032 §5.1.7 step 2) is computed here. Ed448 is reported as unsupported
until it is implemented. Verification only.
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


def _verify_pss(
    spki: bytes, params: bytes | None, tbs: bytes, signature: bytes
) -> tuple[str, str | None]:
    """RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) with EMSA-PSS-VERIFY (§9.1.2)."""
    try:
        options = certinfo.rsa_pss_parameters(params)  # type: ignore[attr-defined]
        em, mod_bits = certinfo.rsa_pss_encoded_message(signature, spki)  # type: ignore[attr-defined]
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
    # `em` is already emLen octets (RFC 8017 §8.1.2 step 2.c), so emBits is
    # modBits - 1 and the leftmost 8*emLen - emBits bits of EM, zero to seven
    # of them, must be zero.
    em_len = len(em)
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
    """PureEdDSA verification (RFC 8032 §5.1.7): hash here, group equation in Rust.

    The signature is `R || S`, and the challenge the group equation needs is
    `SHA-512(R || A || M)` over the encoded point, the encoded public key,
    and the whole message, so nothing but the message is pre-hashed.
    """
    try:
        info = certinfo.parse_spki(spki)  # type: ignore[attr-defined]
    except ValueError as exc:
        outcome = UNSUPPORTED if str(exc).startswith("unsupported") else FAILED
        return outcome, str(exc)
    if algorithm == ED25519:
        if info["algorithm"] != "Ed25519":
            return UNSUPPORTED, "signature algorithm does not match the key type"
        if len(signature) != 64:
            return FAILED, "malformed Ed25519 signature length"
        public_key = info["key_bits"]
        r, s = signature[:32], signature[32:]
        k = hashlib.sha512(r + public_key + tbs).digest()
        verifier = certinfo.eddsa_verify  # type: ignore[attr-defined]
        return _outcome_of(verifier, "Ed25519", public_key, r, s, k)
    return UNSUPPORTED, f"{algorithm} signature verification"
