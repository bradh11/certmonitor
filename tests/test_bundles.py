"""Decoding certificate bundles: PEM, DER, and certs-only PKCS#7."""

import base64
import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from certmonitor import bundles, certinfo
from tests.support import der, pkcs7_certs_only

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHAIN_DER = [(FIXTURES / f"chain_{i}.der").read_bytes() for i in range(3)]
LEAF, INTERMEDIATE, ROOT = CHAIN_DER


def pem_pkcs7(payload: bytes) -> bytes:
    body = base64.encodebytes(payload)
    return b"-----BEGIN PKCS7-----\n" + body + b"-----END PKCS7-----\n"


def test_pem_certificates_decode_in_file_order():
    text = "".join(ssl.DER_cert_to_PEM_cert(der) for der in CHAIN_DER).encode()
    bundle = bundles.certificates_from_bytes(text)
    assert bundle.kind == "pem" and bundle.certificates == CHAIN_DER


def test_a_bare_der_certificate_is_a_bundle_of_one():
    bundle = bundles.certificates_from_bytes(LEAF)
    assert bundle.kind == "der" and bundle.certificates == [LEAF]


def test_der_pkcs7_yields_every_certificate():
    bundle = bundles.certificates_from_bytes(pkcs7_certs_only([ROOT, LEAF]))
    assert bundle.kind == "pkcs7" and bundle.certificates == [ROOT, LEAF]


def test_pem_pkcs7_block_is_decoded():
    bundle = bundles.certificates_from_bytes(pem_pkcs7(pkcs7_certs_only([LEAF])))
    assert bundle.kind == "pkcs7" and bundle.certificates == [LEAF]


def test_pem_certificates_win_over_a_pkcs7_block_in_the_same_file():
    mixed = ssl.DER_cert_to_PEM_cert(ROOT).encode() + pem_pkcs7(
        pkcs7_certs_only([LEAF])
    )
    assert bundles.certificates_from_bytes(mixed).certificates == [ROOT]


@pytest.mark.parametrize(
    "data,fragment",
    [
        (b"", "no certificate data"),
        (b"   \n", "no certificate data"),
        (pkcs7_certs_only([]), "carries no certificates"),
        (pem_pkcs7(pkcs7_certs_only([])), "carries no certificates"),
        (pem_pkcs7(b"\x30\x03\x06\x01\x2a"), "not a PKCS#7"),
        (b"-----BEGIN PKCS7-----\n!!!!\n-----END PKCS7-----\n", "not a PKCS#7"),
        (der(0x30, der(0x06, b"\x2a\x03") + der(0xA0, b"")), "not a PKCS#7"),
    ],
)
def test_undecodable_input_is_a_value_error(data, fragment):
    with pytest.raises(ValueError, match=fragment):
        bundles.certificates_from_bytes(data)


def test_bytes_that_are_neither_are_passed_through_as_one_certificate():
    # Deciding whether they are a certificate is the X.509 parser's job.
    garbage = b"\x30\x03\x02\x01\x01"
    assert bundles.certificates_from_bytes(garbage).certificates == [garbage]


@pytest.mark.parametrize(
    "given",
    [
        [ROOT, LEAF, INTERMEDIATE],
        [INTERMEDIATE, ROOT, LEAF],
        [LEAF, INTERMEDIATE, ROOT],
        [ROOT, INTERMEDIATE, LEAF],
    ],
)
def test_leaf_first_follows_issuer_names(given):
    assert bundles.leaf_first(given) == [LEAF, INTERMEDIATE, ROOT]


def test_leaf_first_keeps_a_partial_chain_and_strays():
    # Without the intermediate the leaf's issuer is absent, so the chain
    # stops there and the root follows in its given position.
    assert bundles.leaf_first([ROOT, LEAF]) == [LEAF, ROOT]
    assert bundles.leaf_first([LEAF]) == [LEAF]
    assert bundles.leaf_first([]) == []


def test_leaf_first_leaves_an_ambiguous_bundle_alone():
    # Two copies of the leaf: neither issued the other and both are
    # end-entity certificates, so there is no single leaf.
    assert bundles.leaf_first([INTERMEDIATE, LEAF, ROOT, LEAF]) == [
        INTERMEDIATE,
        LEAF,
        ROOT,
        LEAF,
    ]
    # Two CAs neither of which issued the other, likewise.
    assert bundles.leaf_first([ROOT, ROOT]) == [ROOT, ROOT]
    not_certificates = [b"\x30\x00", LEAF]
    assert bundles.leaf_first(not_certificates) == not_certificates


def test_the_ca_flag_breaks_a_tie_between_candidates():
    # A root and a leaf with the intermediate missing: neither issued the
    # other, and the end-entity certificate is the leaf.
    assert bundles.leaf_first([ROOT, LEAF]) == [LEAF, ROOT]
    # A root and its intermediate: only the intermediate is unissued here.
    assert bundles.leaf_first([ROOT, INTERMEDIATE]) == [INTERMEDIATE, ROOT]


@pytest.fixture(scope="module")
def self_signed_server(tmp_path_factory):
    """A self-signed end-entity certificate, the kind a lab service presents."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI required to mint a self-signed certificate")
    directory = tmp_path_factory.mktemp("self-signed")
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "s.key",
         "-out", "s.pem", "-days", "1", "-subj", "/CN=lab.test",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "subjectAltName=DNS:lab.test"],
        cwd=directory, check=True, capture_output=True,
    )  # fmt: skip
    return ssl.PEM_cert_to_DER_cert((directory / "s.pem").read_text())


def test_a_self_signed_leaf_is_still_the_leaf(self_signed_server):
    parts = certinfo.certificate_signature_parts(self_signed_server)
    assert parts["subject_der"] == parts["issuer_der"] and parts["is_ca"] is False
    assert bundles.leaf_first([self_signed_server]) == [self_signed_server]
    # Bundled with certificates it never chains to, it still leads: it is
    # the only end-entity certificate nobody issued.
    assert bundles.leaf_first([INTERMEDIATE, ROOT, self_signed_server]) == [
        self_signed_server,
        INTERMEDIATE,
        ROOT,
    ]


def test_openssl_bundles_decode_the_same_way(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI required to build a reference PKCS#7")
    chain = tmp_path / "chain.pem"
    chain.write_text("".join(ssl.DER_cert_to_PEM_cert(der) for der in CHAIN_DER))
    for form, name in (("DER", "chain.p7b"), ("PEM", "chain.p7b.pem")):
        subprocess.run(
            [openssl, "crl2pkcs7", "-nocrl", "-certfile", str(chain), "-outform", form, "-out", str(tmp_path / name)],
            check=True,
            capture_output=True,
        )  # fmt: skip
        bundle = bundles.certificates_from_bytes((tmp_path / name).read_bytes())
        assert bundle.kind == "pkcs7"
        assert sorted(bundle.certificates) == sorted(CHAIN_DER)
    assert (
        certinfo.pkcs7_certificates((tmp_path / "chain.p7b").read_bytes())
        == bundle.certificates
    )
