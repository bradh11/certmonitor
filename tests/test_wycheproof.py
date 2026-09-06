"""Signature verification against Google's Wycheproof vectors.

Each vector is a public key, a message, a signature, and the expected
verdict. `valid` must verify. `invalid` must be rejected, either by
returning False or by refusing malformed input with `ValueError`; the
vectors deliberately include BER-encoded signatures, out-of-range values,
leading zeros, and padding tricks, which a strict verifier rejects either
way. `acceptable` may go either way.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certmonitor import certinfo

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"
ALGORITHMS = {
    ("ECDSA", "SHA-256"): "1.2.840.10045.4.3.2",
    ("ECDSA", "SHA-384"): "1.2.840.10045.4.3.3",
    ("ECDSA", "SHA-512"): "1.2.840.10045.4.3.4",
    ("RSASSA-PKCS1-v1_5", "SHA-256"): "1.2.840.113549.1.1.11",
    ("RSASSA-PKCS1-v1_5", "SHA-384"): "1.2.840.113549.1.1.12",
    ("RSASSA-PKCS1-v1_5", "SHA-512"): "1.2.840.113549.1.1.13",
}
HASHES = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}


def load_cases():
    cases = []
    for path in sorted(VECTORS.glob("*.json")):
        data = json.loads(path.read_text())
        for group in data["testGroups"]:
            algorithm = ALGORITHMS[(data["algorithm"], group["sha"])]
            key = bytes.fromhex(group["publicKeyDer"])
            hash_name = HASHES[group["sha"]]
            for test in group["tests"]:
                cases.append(
                    pytest.param(
                        algorithm,
                        hash_name,
                        key,
                        test,
                        id=f"{path.stem}-{test['tcId']}",
                    )
                )
    return cases


def verdict(algorithm, hash_name, key, test):
    digest = hashlib.new(hash_name, bytes.fromhex(test["msg"])).digest()
    try:
        return certinfo.verify_signature(
            algorithm, digest, bytes.fromhex(test["sig"]), key
        )
    except ValueError:
        return False


@pytest.mark.parametrize("algorithm,hash_name,key,test", load_cases())
def test_wycheproof_vector(algorithm, hash_name, key, test):
    result = verdict(algorithm, hash_name, key, test)
    if test["result"] == "valid":
        assert result is True, f"tcId {test['tcId']}: {test['comment']} {test['flags']}"
    elif test["result"] == "invalid":
        assert result is False, (
            f"tcId {test['tcId']}: {test['comment']} {test['flags']}"
        )


def test_vector_files_are_complete():
    files = sorted(p.name for p in VECTORS.glob("*.json"))
    assert files == [
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256r1_sha512_test.json",
        "ecdsa_secp384r1_sha384_test.json",
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha384_test.json",
    ]
    for path in VECTORS.glob("*.json"):
        data = json.loads(path.read_text())
        assert sum(len(g["tests"]) for g in data["testGroups"]) == data["numberOfTests"]
