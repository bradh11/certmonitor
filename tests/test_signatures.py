"""Signature-algorithm primitives exposed by the Rust extension: RSASSA-PSS
parameter parsing (RFC 4055), the raw RSA public-key operation (RFC 8017
§5.2.2 RSAVP1), and the Ed25519 group equation (RFC 8032 §5.1.7); and the
scheme dispatch, padding checks, and challenge hashing in
`certmonitor.signatures` that build on them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certmonitor import certinfo, signatures
from tests.support import pss_params

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"

# A 2049-bit RSA key, so that modBits is 1 mod 8 and emLen is one octet
# shorter than the modulus. Produced offline in pure Python (Miller-Rabin
# primes of 1025 and 1024 bits, e = 65537) with an RFC 8017 §9.1.1 PSS
# signature over MESSAGE_2049 using SHA-256, MGF1-SHA-256, and a 32-byte
# salt, then cross-checked with `openssl pkeyutl -verify -pubin -inkey
# spki.der -keyform DER -pkeyopt rsa_padding_mode:pss -pkeyopt
# rsa_pss_saltlen:32 -pkeyopt digest:sha256`, which reported "Signature
# Verified Successfully".
SPKI_2049 = bytes.fromhex(
    "30820122300d06092a864886f70d01010105000382010f003082010a0282"
    "010101794c399192be517340219300a6d779563532203dad40b9809464b0"
    "97dc64f1c38dea014397eb94052b3c3ffdfe39ab2f3a88a271bbf6248235"
    "85bfe776f03c6e8d6bab68273e2ff4f130e6dd379937fb54ed7cfb29d206"
    "514a668241f8d33567c17483e0fdd419d6d0a5f690d1e3b48be30de0ff6c"
    "9f33dc16bab4403c65a281069a17ef96767259ed9b476f5565320f8b1fcd"
    "8cfcbec3f0015d68614d4621f22bf60404f90863c88cf03b465996f8c22c"
    "dfb324dbcdaa64d39584cb7a0228d86629b0cc4f457979bf13816df6e0d6"
    "32bb7dfaac38c2d1011b29ad9414fc06bf46a8b282349e8edc8be90f8fa0"
    "ecb59609d5c9b474a43cc364ca9e45f9aa2e350203010001"
)

SIG_2049 = bytes.fromhex(
    "0069c98ba788f01569b220625ae8babb1ebc9952172081a11a5beeb19a27"
    "4b4074b0744710a1f34c87142b1146701ec0caa7c72322d53199543e498c"
    "d19e1b4c1944ee249867bc43fef58d52973904b71ded793f4e085599b641"
    "419176c6734a8ea7b9f736634aa8deab1466e4d07040137d20100c61c7a0"
    "647280014e1a704118d4b1acbf4a69a0f899ceca6116fedcc04c1ddfae98"
    "1a3d2ff68f74880a1c0fc0462fff60b25544a82d273f658068e528c8e598"
    "3770ef9478c587001d3b9f5b483fac5f29b87c15b7ca1bdf8d9e66c4b6a7"
    "08e80410fc334b417cc9288057e467d783257b620b87d5cb48657a11420b"
    "01d2f81a536567b3369649288534a6e5f8"
)
MESSAGE_2049 = b"certmonitor pss 2049"

# RFC 8032 §7.1 test 3: a two-byte message, wrapped in the RFC 8410 §4
# SubjectPublicKeyInfo an X.509 signer would carry it in.
ED25519_SPKI = bytes.fromhex(
    "302a300506032b6570032100"
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)
ED25519_MESSAGE = bytes.fromhex("af82")
ED25519_SIGNATURE = bytes.fromhex(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
)


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


def test_rsa_pss_encoded_message_recovers_the_encoded_message():
    data = json.loads((VECTORS / "rsa_signature_2048_sha256_test.json").read_text())
    group = data["testGroups"][0]
    spki_der = bytes.fromhex(group["publicKeyDer"])
    valid = next(test for test in group["tests"] if test["result"] == "valid")
    em, mod_bits = certinfo.rsa_pss_encoded_message(
        bytes.fromhex(valid["sig"]), spki_der
    )
    # 2048 is 0 mod 8, so emLen equals k and this PKCS#1 v1.5 EM survives
    # the emLen truncation whole, block type included.
    assert len(em) == 256
    assert mod_bits == 2048
    assert em[:2] == b"\x00\x01"


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


def test_pss_with_malformed_mgf_parameters_fails(rsa_spki):
    # maskGenAlgorithm with an unknown OID
    params = bytes.fromhex("3016a00f300d06096086480165030402010500a103020120")
    outcome, why = signatures.verify(
        rsa_spki, signatures.RSASSA_PSS, params, b"tbs", b"\x00" * 256
    )
    # `openssl asn1parse` shows [1] wrapping an INTEGER rather than the
    # AlgorithmIdentifier SEQUENCE the maskGenAlgorithm field requires, so
    # the parser rejects this as malformed before it ever inspects an OID.
    assert outcome == signatures.FAILED and "malformed" in why


def test_pss_with_an_unknown_mgf_is_unsupported(rsa_spki):
    # A well-formed maskGenAlgorithm naming OID 1.2.3.4, which is not MGF1
    # (the only mask generation function RFC 4055 §A.2.3 defines for PSS).
    params = bytes.fromhex("301aa00f300d06096086480165030402010500a107300506032a0304")
    outcome, why = signatures.verify(
        rsa_spki, signatures.RSASSA_PSS, params, b"tbs", b"\x00" * 256
    )
    assert outcome == signatures.UNSUPPORTED and "1.2.3.4" in why


def test_pss_verifies_under_a_modulus_whose_bit_length_is_one_mod_eight():
    # RFC 8017 §8.1.2 step 2.c: emLen is ceil((modBits - 1) / 8), one octet
    # shorter than the modulus when modBits is 1 mod 8.
    params = pss_params("sha256", "sha256", 32)
    assert signatures.verify(
        SPKI_2049, signatures.RSASSA_PSS, params, MESSAGE_2049, SIG_2049
    ) == (signatures.VERIFIED, None)
    assert (
        signatures.verify(
            SPKI_2049, signatures.RSASSA_PSS, params, MESSAGE_2049 + b"!", SIG_2049
        )[0]
        == signatures.FAILED
    )


def test_parse_spki_reports_the_key_type_and_its_bits():
    info = certinfo.parse_spki(ED25519_SPKI)
    assert info["algorithm"] == "Ed25519"
    assert info["curve"] is None
    assert info["key_bits"] == ED25519_SPKI[-32:]


def test_parse_spki_rejects_bytes_that_are_not_a_subject_public_key_info():
    with pytest.raises(ValueError, match="malformed SubjectPublicKeyInfo"):
        certinfo.parse_spki(b"\x30\x00")


def test_ed25519_verifies_an_rfc8032_vector():
    assert signatures.verify(
        ED25519_SPKI, signatures.ED25519, None, ED25519_MESSAGE, ED25519_SIGNATURE
    ) == (signatures.VERIFIED, None)


def test_ed25519_rejects_a_changed_message_and_a_changed_signature():
    outcome, why = signatures.verify(
        ED25519_SPKI,
        signatures.ED25519,
        None,
        ED25519_MESSAGE + b"!",
        ED25519_SIGNATURE,
    )
    assert (outcome, why) == (signatures.FAILED, "signature does not verify")
    tampered = bytearray(ED25519_SIGNATURE)
    tampered[0] ^= 1
    assert (
        signatures.verify(
            ED25519_SPKI, signatures.ED25519, None, ED25519_MESSAGE, bytes(tampered)
        )[0]
        == signatures.FAILED
    )


def test_ed25519_rejects_a_signature_that_is_not_sixty_four_bytes():
    outcome, why = signatures.verify(
        ED25519_SPKI,
        signatures.ED25519,
        None,
        ED25519_MESSAGE,
        ED25519_SIGNATURE + b"\x00",
    )
    assert outcome == signatures.FAILED and "signature length" in why


def test_ed25519_over_a_key_that_is_not_an_edwards_key_is_unsupported(rsa_spki):
    outcome, why = signatures.verify(
        rsa_spki, signatures.ED25519, None, ED25519_MESSAGE, ED25519_SIGNATURE
    )
    assert outcome == signatures.UNSUPPORTED and "key type" in why


def test_ed25519_with_a_malformed_signer_key_fails():
    outcome, why = signatures.verify(
        b"\x30\x00", signatures.ED25519, None, ED25519_MESSAGE, ED25519_SIGNATURE
    )
    assert outcome == signatures.FAILED and "malformed" in why


def test_ed448_is_still_unsupported():
    # The OID is recognised and routed, the curve is not implemented yet.
    outcome, why = signatures.verify(
        ED25519_SPKI, signatures.ED448, None, ED25519_MESSAGE, ED25519_SIGNATURE
    )
    assert outcome == signatures.UNSUPPORTED and signatures.ED448 in why
