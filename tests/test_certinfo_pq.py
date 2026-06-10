# tests/test_certinfo_pq.py
#
# Round-trip tests for post-quantum algorithm recognition in the Rust
# ``certmonitor.certinfo`` module (issue #29). Synthetic certificates are
# built by hand-encoding DER below — no real PQ web-PKI certs exist to
# capture yet, and the SPKI shape (algorithm OID with absent parameters
# plus an opaque BIT STRING) is fixed by RFC 9881 / RFC 9909.

import pytest

from certmonitor import certinfo

# OID body bytes (no tag/length), mirroring rust_certinfo/src/der/oid.rs.
ML_DSA_65 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
SLH_DSA_SHA2_128S = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14])
# id-MLDSA65-ECDSA-P256-SHA512 = 1.3.6.1.5.5.7.6.45
COMPOSITE_MLDSA65_P256 = bytes([0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2D])
RSA_ENCRYPTION = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])

# ML-DSA-65 public keys are 1952 bytes (FIPS 204 table 2).
ML_DSA_65_KEY_LEN = 1952


def _tlv(tag: int, body: bytes) -> bytes:
    """Encode one DER TLV with short- or long-form length."""
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + body


def _alg_id(oid_body: bytes) -> bytes:
    """AlgorithmIdentifier with absent parameters (the PQ form)."""
    return _tlv(0x30, _tlv(0x06, oid_body))


def _minimal_cert(spki_alg_oid: bytes, key_len: int) -> bytes:
    """Build the smallest Certificate the parser accepts: version absent,
    empty issuer/subject Names, UTCTime validity, no extensions. The
    signatureAlgorithm reuses the SPKI OID, matching how ML-DSA certs use
    one OID for both key and signature."""
    serial = _tlv(0x02, b"\x01")
    sig_alg = _alg_id(spki_alg_oid)
    empty_name = _tlv(0x30, b"")
    validity = _tlv(0x30, _tlv(0x17, b"250101000000Z") + _tlv(0x17, b"350101000000Z"))
    spki = _tlv(0x30, _alg_id(spki_alg_oid) + _tlv(0x03, b"\x00" + b"\x00" * key_len))
    tbs = _tlv(0x30, serial + sig_alg + empty_name + validity + empty_name + spki)
    signature_value = _tlv(0x03, b"\x00\x00")
    return _tlv(0x30, tbs + sig_alg + signature_value)


class TestParsePublicKeyInfoPq:
    def test_ml_dsa_65(self):
        der = _minimal_cert(ML_DSA_65, ML_DSA_65_KEY_LEN)
        info = certinfo.parse_public_key_info(der)
        assert info == {
            "algorithm": "ml-dsa-65",
            "size": ML_DSA_65_KEY_LEN * 8,
            "curve": None,
        }

    def test_slh_dsa_sha2_128s(self):
        der = _minimal_cert(SLH_DSA_SHA2_128S, 32)
        info = certinfo.parse_public_key_info(der)
        assert info["algorithm"] == "slh-dsa-sha2-128s"
        assert info["size"] == 256
        assert info["curve"] is None

    def test_composite_mldsa(self):
        der = _minimal_cert(COMPOSITE_MLDSA65_P256, 1952 + 65)
        info = certinfo.parse_public_key_info(der)
        assert info["algorithm"] == "mldsa65-ecdsa-p256-sha512"
        assert info["curve"] is None

    def test_dict_shape_unchanged(self):
        """The PQ path must keep the exact {algorithm, size, curve} shape."""
        der = _minimal_cert(ML_DSA_65, ML_DSA_65_KEY_LEN)
        info = certinfo.parse_public_key_info(der)
        assert set(info.keys()) == {"algorithm", "size", "curve"}

    def test_rsa_regression_unchanged(self):
        """A synthetic non-PQ algorithm path is untouched: an RSA OID with a
        non-RSA body parses as before (the corpus tests cover real RSA/EC
        certs; this guards the dispatch order in ``parsed()``)."""
        der = _minimal_cert(RSA_ENCRYPTION, 16)
        info = certinfo.parse_public_key_info(der)
        # Malformed RSA body (not a SEQUENCE) collapses to unknown — same
        # behavior as before the PQ table existed.
        assert info["algorithm"] == "unknown"


class TestAnalyzeChainPq:
    def test_pq_leaf_in_chain_analysis(self):
        der = _minimal_cert(ML_DSA_65, ML_DSA_65_KEY_LEN)
        analysis = certinfo.analyze_chain([der])
        assert analysis["chain_length"] == 1
        leaf = analysis["certs"][0]
        assert leaf["public_key_info"]["algorithm"] == "ml-dsa-65"
        assert leaf["signature_algorithm_oid"] == "2.16.840.1.101.3.4.3.18"
        assert leaf["signature_algorithm_weak"] is False

    def test_extract_public_key_der_roundtrip(self):
        der = _minimal_cert(ML_DSA_65, ML_DSA_65_KEY_LEN)
        spki_der = certinfo.extract_public_key_der(der)
        # The extracted SPKI must itself be the SPKI we embedded.
        assert spki_der.startswith(b"\x30")
        assert ML_DSA_65 in spki_der

    def test_unknown_oid_unaffected(self):
        # 1.2.3.4 — not RSA, not EC, not in the PQ table.
        der = _minimal_cert(bytes([0x2A, 0x03, 0x04]), 16)
        info = certinfo.parse_public_key_info(der)
        assert info == {"algorithm": "unknown", "size": 0, "curve": None}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
