"""Signature verification against Google's Wycheproof vectors.

Each vector is a public key, a message, a signature, and the expected
verdict. `valid` must verify. `invalid` must be rejected, either by
returning False or by refusing malformed input with `ValueError`; the
vectors deliberately include BER-encoded signatures, out-of-range values,
leading zeros, and padding tricks, which a strict verifier rejects either
way. `acceptable` may go either way.

ECDSA and RSASSA-PKCS1-v1_5 vectors are checked with `certinfo.verify_signature`
directly. RSASSA-PSS vectors carry no algorithm parameters of their own, so
`tests.support.pss_params` builds the `RSASSA-PSS-params` DER (RFC 4055
§3.1) from each test group's `sha`, `mgfSha`, and `sLen` fields (groups
naming a mask generation function other than MGF1 are skipped), and the check goes
through `certmonitor.signatures.verify`, which is where the PSS padding is
implemented. Two of the PSS files exist to pin the parameters RFC 8017 §8.1
lets a signer choose independently of the message hash: one names SHA-1 as the
MGF1 hash where the message hash is SHA-256, the other a zero-length salt where
the digest is 32 bytes. A third, `rsa_pss_2048_sha256_mgf1_32_params_test.json`,
carries the same parameters in the key itself: its `publicKeyDer` names
`id-RSASSA-PSS` (RFC 4055 §1.2) with `RSASSA-PSS-params`, so verifying it
exercises both that key encoding and the RFC 4055 §3.3 check that the
signature's parameters satisfy the key's. EdDSA vectors go through
`signatures.verify` too, since that is where the challenge hash is computed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certmonitor import certinfo, signatures
from tests.support import pss_params

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"
ALGORITHMS = {
    ("ECDSA", "SHA-256"): "1.2.840.10045.4.3.2",
    ("ECDSA", "SHA-384"): "1.2.840.10045.4.3.3",
    ("ECDSA", "SHA-512"): "1.2.840.10045.4.3.4",
    ("RSASSA-PKCS1-v1_5", "SHA-256"): "1.2.840.113549.1.1.11",
    ("RSASSA-PKCS1-v1_5", "SHA-384"): "1.2.840.113549.1.1.12",
    ("RSASSA-PKCS1-v1_5", "SHA-512"): "1.2.840.113549.1.1.13",
}
HASHES = {
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}
EDDSA_OIDS = {"Ed25519": signatures.ED25519, "Ed448": signatures.ED448}


def load_cases():
    cases = []
    for path in sorted(VECTORS.glob("*.json")):
        data = json.loads(path.read_text())
        for group in data["testGroups"]:
            key = bytes.fromhex(group["publicKeyDer"])
            if data["algorithm"] == "RSASSA-PSS":
                # `pss_params` encodes MGF1, the only mask generation function
                # RFC 4055 §A.2.3 defines for PSS, so a group naming anything
                # else is not one these parameters could describe.
                if group["mgf"] != "MGF1":
                    continue
                params = pss_params(
                    HASHES[group["sha"]], HASHES[group["mgfSha"]], group["sLen"]
                )
                via_signatures, scheme = True, (signatures.RSASSA_PSS, params)
            elif data["algorithm"] == "EDDSA":
                # Both files carry the algorithm name `EDDSA`, and a group
                # names no algorithm of its own, so the curve comes from the
                # key.
                curve = certinfo.parse_spki(key)["algorithm"]
                via_signatures, scheme = True, (EDDSA_OIDS[curve], None)
            else:
                algorithm = ALGORITHMS[(data["algorithm"], group["sha"])]
                via_signatures, scheme = False, (algorithm, HASHES[group["sha"]])
            for test in group["tests"]:
                cases.append(
                    pytest.param(
                        via_signatures,
                        scheme,
                        key,
                        test,
                        id=f"{path.stem}-{test['tcId']}",
                    )
                )
    return cases


def verdict(via_signatures, scheme, key, test):
    if via_signatures:
        algorithm, params = scheme
        message = bytes.fromhex(test["msg"])
        outcome, _ = signatures.verify(
            key, algorithm, params, message, bytes.fromhex(test["sig"])
        )
        return outcome == signatures.VERIFIED
    algorithm, hash_name = scheme
    digest = hashlib.new(hash_name, bytes.fromhex(test["msg"])).digest()
    try:
        return certinfo.verify_signature(
            algorithm, digest, bytes.fromhex(test["sig"]), key
        )
    except ValueError:
        return False


@pytest.mark.parametrize("via_signatures,scheme,key,test", load_cases())
def test_wycheproof_vector(via_signatures, scheme, key, test):
    result = verdict(via_signatures, scheme, key, test)
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
        "ecdsa_secp521r1_sha512_test.json",
        "ed25519_test.json",
        "ed448_test.json",
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        "rsa_pss_2048_sha256_mgf1_32_params_test.json",
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha256_mgf1sha1_20_test.json",
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha384_test.json",
    ]
    for path in VECTORS.glob("*.json"):
        data = json.loads(path.read_text())
        assert sum(len(g["tests"]) for g in data["testGroups"]) == data["numberOfTests"]
