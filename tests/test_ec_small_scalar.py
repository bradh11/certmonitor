"""`certinfo.ec_small_scalar`: recovering an EC private key from the public
key alone when the private scalar is tiny.

The fixtures are the eight eMudhra intermediate CA certificates revoked in
October 2026, whose P-384 private keys were generated as integers below 256.
`tests/fixtures/emudhra/README.md` records where they came from and how the
expected scalars were found with OpenSSL, independently of CertMonitor.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from certmonitor import certinfo

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EMUDHRA = FIXTURES / "emudhra"

EMUDHRA_SCALARS = {
    "EM-DV-TLS-CA-G3B": 156,
    "EM-DV-TLS-CA-G3C": 230,
    "EM-EV-TLS-CA-G3B": 115,
    "EM-EV-TLS-CA-G3C": 56,
    "EM-OV-CS-CA-G3B": 66,
    "EM-OV-CS-CA-G3C": 237,
    "EM-OV-TLS-CA-G3B": 155,
    "EM-OV-TLS-CA-G3C": 4,
}

# P-384 field prime and group order (FIPS 186-4 D.1.2.4).
P384_P = int(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    16,
)
P384_N = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    16,
)


def emudhra_spki(name: str) -> bytes:
    pem = (EMUDHRA / f"{name}.crt.pem").read_text()
    return certinfo.extract_public_key_der(ssl.PEM_cert_to_DER_cert(pem))


@pytest.mark.parametrize(("name", "scalar"), sorted(EMUDHRA_SCALARS.items()))
def test_every_emudhra_intermediate_gives_up_its_private_key(
    name: str, scalar: int
) -> None:
    assert certinfo.ec_small_scalar(emudhra_spki(name), 256) == scalar


def test_a_bound_below_the_scalar_finds_nothing() -> None:
    assert certinfo.ec_small_scalar(emudhra_spki("EM-OV-CS-CA-G3C"), 236) is None


def test_a_negated_key_comes_back_as_its_full_private_scalar() -> None:
    # Flipping y turns the key [4]G into -[4]G, which is [n - 4]G. The
    # private key is then n - 4, a 384-bit integer, and that is what must
    # come back, not 4.
    spki = emudhra_spki("EM-OV-TLS-CA-G3C")
    y = int.from_bytes(spki[-48:], "big")
    negated = spki[:-48] + (P384_P - y).to_bytes(48, "big")
    assert certinfo.ec_small_scalar(negated, 256) == P384_N - 4


def test_a_properly_generated_key_reports_none() -> None:
    leaf = (FIXTURES / "chain_0.der").read_bytes()  # www.google.com, EC
    assert certinfo.ec_small_scalar(certinfo.extract_public_key_der(leaf), 256) is None


def test_an_rsa_key_raises_value_error() -> None:
    intermediate = (FIXTURES / "chain_1.der").read_bytes()  # Google WR2, RSA
    with pytest.raises(ValueError, match="not an EC key"):
        certinfo.ec_small_scalar(certinfo.extract_public_key_der(intermediate), 256)


def test_a_malformed_key_raises_value_error() -> None:
    with pytest.raises(ValueError, match="SubjectPublicKeyInfo"):
        certinfo.ec_small_scalar(b"\x30\x00", 256)


def test_a_bound_above_the_ceiling_raises_value_error() -> None:
    with pytest.raises(ValueError, match="bound above 16777216"):
        certinfo.ec_small_scalar(emudhra_spki("EM-OV-TLS-CA-G3C"), (1 << 24) + 1)


def test_a_negative_bound_is_refused() -> None:
    with pytest.raises(OverflowError):
        certinfo.ec_small_scalar(emudhra_spki("EM-OV-TLS-CA-G3C"), -1)
