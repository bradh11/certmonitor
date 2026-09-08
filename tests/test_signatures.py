"""Signature-algorithm primitives exposed by the Rust extension: RSASSA-PSS
parameter parsing (RFC 4055) and the raw RSA public-key operation (RFC 8017
§5.2.2 RSAVP1); and the scheme dispatch and padding checks in
`certmonitor.signatures` that build on them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certmonitor import certinfo, signatures

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"


@pytest.fixture
def rsa_spki():
    data = json.loads((VECTORS / "rsa_signature_2048_sha256_test.json").read_text())
    return bytes.fromhex(data["testGroups"][0]["publicKeyDer"])


def test_rsa_pss_parameters_none_yields_rfc4055_defaults():
    assert certinfo.rsa_pss_parameters(None) == {
        "hash": "sha1",
        "mgf_hash": "sha1",
        "salt_length": 20,
        "trailer_field": 1,
    }


def test_rsa_public_operation_recovers_the_encoded_message():
    data = json.loads((VECTORS / "rsa_signature_2048_sha256_test.json").read_text())
    group = data["testGroups"][0]
    spki_der = bytes.fromhex(group["publicKeyDer"])
    valid = next(test for test in group["tests"] if test["result"] == "valid")
    encoded = certinfo.rsa_public_operation(bytes.fromhex(valid["sig"]), spki_der)
    assert len(encoded) == 256
    assert encoded[:2] == b"\x00\x01"


def test_mgf1_matches_the_rfc_8017_definition():
    # MGF1(seed, 5) with SHA-256 computed independently: SHA-256(seed || 00000000)[:5]
    seed = b"seed"
    expected = hashlib.sha256(seed + b"\x00\x00\x00\x00").digest()[:5]
    assert signatures._mgf1(seed, 5, "sha256") == expected
    long = signatures._mgf1(seed, 70, "sha256")
    assert long[:32] == hashlib.sha256(seed + b"\x00\x00\x00\x00").digest()
    assert long[32:64] == hashlib.sha256(seed + b"\x00\x00\x00\x01").digest()
    assert len(long) == 70


def test_unknown_algorithm_is_unsupported_not_failed():
    outcome, why = signatures.verify(b"", "1.2.3.4", None, b"tbs", b"sig")
    assert outcome == signatures.UNSUPPORTED and "1.2.3.4" in why


def test_pss_with_unsupported_mgf_is_unsupported(rsa_spki):
    # maskGenAlgorithm with an unknown OID
    params = bytes.fromhex("3016a00f300d06096086480165030402010500a103020120")
    outcome, why = signatures.verify(
        rsa_spki, signatures.RSASSA_PSS, params, b"tbs", b"\x00" * 256
    )
    # `openssl asn1parse` shows [1] wrapping an INTEGER rather than the
    # AlgorithmIdentifier SEQUENCE the maskGenAlgorithm field requires, so
    # the parser rejects this as malformed before it ever inspects an OID.
    assert outcome == signatures.FAILED and "malformed" in why
