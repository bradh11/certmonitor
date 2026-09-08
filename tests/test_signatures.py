"""Signature-algorithm primitives exposed by the Rust extension: RSASSA-PSS
parameter parsing (RFC 4055), the raw RSA public-key operation (RFC 8017
§5.2.2 RSAVP1), and the EdDSA group equation (RFC 8032 §5.1.7, §5.2.7); and the
scheme dispatch, padding checks, and challenge hashing in
`certmonitor.signatures` that build on them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certmonitor import certinfo, signatures
from tests.support import der, pss_params

VECTORS = Path(__file__).resolve().parent / "fixtures" / "wycheproof"

# `AlgorithmIdentifier { rsaEncryption, NULL }`, the whole 15-byte TLV every
# RSA SubjectPublicKeyInfo in the vectors carries, and the id-RSASSA-PSS OID
# that replaces it below.
RSA_ENCRYPTION_ALGORITHM_IDENTIFIER = bytes.fromhex("300d06092a864886f70d0101010500")
OID_RSASSA_PSS = bytes.fromhex("2a864886f70d01010a")
# The restrictions an id-RSASSA-PSS key carries in the tests below: SHA-256,
# MGF1-SHA-256, and a 32-byte salt.
KEY_PSS_PARAMS = pss_params("sha256", "sha256", 32)


def pss_keyed_spki(rsa_spki_der: bytes, params: bytes) -> bytes:
    """`rsa_spki_der` with its AlgorithmIdentifier rewritten to id-RSASSA-PSS.

    RFC 4055 §1.2 lets a CA encode an RSA key this way, with `params` as the
    optional `RSASSA-PSS-params`. The subjectPublicKey is the same
    RSAPublicKey either way, so it is carried over untouched.
    """
    at = rsa_spki_der.index(RSA_ENCRYPTION_ALGORITHM_IDENTIFIER)
    bit_string = rsa_spki_der[at + len(RSA_ENCRYPTION_ALGORITHM_IDENTIFIER) :]
    algorithm = der(0x30, der(0x06, OID_RSASSA_PSS) + params)
    return der(0x30, algorithm + bit_string)


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

# RFC 8032 §7.4 "1 octet", in the same RFC 8410 §4 wrapper.
ED448_SPKI = bytes.fromhex(
    "3043300506032b6571033a00"
    "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
    "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
)
ED448_MESSAGE = bytes.fromhex("03")
ED448_SIGNATURE = bytes.fromhex(
    "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
    "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb"
    "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f"
    "f3348ab21aa4adafd1d234441cf807c03a00"
)
# The challenge that vector's signature needs, `SHAKE256(dom4(0, "") || R
# || A || M, 114)`; `signatures.verify` computes it, and the error-contract
# test below hands it to `certinfo.eddsa_verify` directly.
ED448_CHALLENGE = bytes.fromhex(
    "a1e2cb4e8b7dd00631d36979c28c729b5dfed35ed27ba5c351ea2ec9fbfec332"
    "e6f091cf2e1453d9c9536a2b5b96ee16bbba8b52d597b817f1d949834a77046d"
    "5e04442877d8c18ff7067ab08e9bbb57013a19555d8227967206ffd4e18ccfc7"
    "53bc1fb19a07f8a2003019b3ae911634a49f"
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


def test_parse_spki_reports_an_rsassa_pss_key_and_its_parameters(rsa_spki):
    # RFC 4055 §1.2: the same RSA key, named by id-RSASSA-PSS and carrying
    # the parameters that restrict it.
    info = certinfo.parse_spki(pss_keyed_spki(rsa_spki, KEY_PSS_PARAMS))
    assert info["algorithm"] == "rsassaPss"
    assert info["size"] == 2048
    assert info["algorithm_params"] == KEY_PSS_PARAMS
    # rsaEncryption's parameters are NULL, which `parse_spki` reports as
    # absent, so an unrestricted key is plainly distinguishable.
    plain = certinfo.parse_spki(rsa_spki)
    assert plain["algorithm"] == "rsaEncryption"
    assert plain["algorithm_params"] is None


def test_pss_signature_parameters_must_satisfy_the_keys_restrictions(rsa_spki):
    # RFC 4055 §3.3: with the key's parameters present, a signature may only
    # use the same hash and MGF hash and a salt at least as long.
    spki = pss_keyed_spki(rsa_spki, KEY_PSS_PARAMS)
    for hash_name, mgf_hash, salt_length in (
        ("sha384", "sha384", 48),
        ("sha256", "sha384", 32),
        ("sha256", "sha256", 31),
    ):
        outcome, why = signatures.verify(
            spki,
            signatures.RSASSA_PSS,
            pss_params(hash_name, mgf_hash, salt_length),
            b"tbs",
            b"\x00" * 256,
        )
        assert outcome == signatures.FAILED
        assert "RSASSA-PSS restrictions" in why


def test_pss_signature_may_use_a_longer_salt_than_the_key_requires(rsa_spki):
    # The salt length is a floor, not an equality, so a 64-byte salt gets
    # past the restriction check and is judged on its padding alone.
    spki = pss_keyed_spki(rsa_spki, KEY_PSS_PARAMS)
    outcome, why = signatures.verify(
        spki,
        signatures.RSASSA_PSS,
        pss_params("sha256", "sha256", 64),
        b"tbs",
        b"\x00" * 256,
    )
    assert outcome == signatures.FAILED
    assert "RSASSA-PSS restrictions" not in why


def test_pkcs1_v15_under_an_rsassa_pss_key_is_refused(rsa_spki):
    # RFC 4055 §3.3 again, from the other side: the Rust verifier will not
    # check a PKCS#1 v1.5 signature under a key restricted to PSS. This is
    # a policy violation by the signer, not an algorithm CertMonitor lacks,
    # so it is malformed rather than unsupported.
    spki = pss_keyed_spki(rsa_spki, KEY_PSS_PARAMS)
    digest = hashlib.sha256(b"tbs").digest()
    with pytest.raises(ValueError, match="^malformed"):
        certinfo.verify_signature("1.2.840.113549.1.1.11", digest, b"\x00" * 256, spki)


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


def test_ed448_verifies_an_rfc8032_vector():
    assert signatures.verify(
        ED448_SPKI, signatures.ED448, None, ED448_MESSAGE, ED448_SIGNATURE
    ) == (signatures.VERIFIED, None)


def test_ed448_rejects_a_changed_message_and_a_changed_signature():
    outcome, why = signatures.verify(
        ED448_SPKI,
        signatures.ED448,
        None,
        ED448_MESSAGE + b"!",
        ED448_SIGNATURE,
    )
    assert (outcome, why) == (signatures.FAILED, "signature does not verify")
    tampered = bytearray(ED448_SIGNATURE)
    tampered[0] ^= 1
    assert (
        signatures.verify(
            ED448_SPKI, signatures.ED448, None, ED448_MESSAGE, bytes(tampered)
        )[0]
        == signatures.FAILED
    )


def test_ed448_rejects_a_signature_that_is_not_a_hundred_and_fourteen_bytes():
    outcome, why = signatures.verify(
        ED448_SPKI,
        signatures.ED448,
        None,
        ED448_MESSAGE,
        ED448_SIGNATURE + b"\x00",
    )
    assert outcome == signatures.FAILED and "signature length" in why


def test_each_edwards_oid_needs_its_own_curve():
    # The two OIDs are separate algorithms (RFC 8410 §3), so an Ed448 key
    # cannot answer for the Ed25519 OID or the other way round.
    outcome, why = signatures.verify(
        ED448_SPKI, signatures.ED25519, None, ED448_MESSAGE, ED448_SIGNATURE
    )
    assert outcome == signatures.UNSUPPORTED and "key type" in why
    outcome, why = signatures.verify(
        ED25519_SPKI, signatures.ED448, None, ED25519_MESSAGE, ED25519_SIGNATURE
    )
    assert outcome == signatures.UNSUPPORTED and "key type" in why


def test_eddsa_verify_reports_its_errors():
    # The three things `certinfo.eddsa_verify` can say about its inputs,
    # which `signatures.verify` translates but never surfaces verbatim.
    with pytest.raises(ValueError, match="^unsupported EdDSA curve"):
        certinfo.eddsa_verify(
            "X25519", b"\x00" * 32, b"\x00" * 32, b"\x00" * 32, b"\x00" * 64
        )
    with pytest.raises(ValueError, match="^malformed"):
        certinfo.eddsa_verify(
            "Ed25519", b"\x00" * 31, b"\x00" * 32, b"\x00" * 32, b"\x00" * 64
        )
    assert (
        certinfo.eddsa_verify(
            "Ed448",
            ED448_SPKI[-57:],
            ED448_SIGNATURE[:57],
            ED448_SIGNATURE[57:],
            ED448_CHALLENGE,
        )
        is True
    )


def test_eddsa_challenge_rejects_a_curve_not_in_its_table():
    # A third curve name must raise rather than silently falling through
    # to the Ed448 challenge hash.
    with pytest.raises(ValueError, match="^unsupported EdDSA curve Ed12345$"):
        signatures._eddsa_challenge("Ed12345", b"\x00" * 32, b"\x00" * 32, b"tbs")
