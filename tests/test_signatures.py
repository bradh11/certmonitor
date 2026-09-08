"""Signature-algorithm primitives exposed by the Rust extension: RSASSA-PSS
parameter parsing (RFC 4055) and the raw RSA public-key operation (RFC 8017
§5.2.2 RSAVP1). This module starts small and grows with the RSASSA-PSS
verification path (Task 3 of the signature-algorithm plan).
"""

from __future__ import annotations

import json
from pathlib import Path

from certmonitor import certinfo

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"


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
