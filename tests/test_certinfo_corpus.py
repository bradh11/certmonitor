# tests/test_certinfo_corpus.py
#
# Snapshot-style regression tests for the in-tree DER parser. Runs every
# captured cert in `tests/fixtures/diff_corpus/` (~130 unique certs from
# 101 production hosts) through every public `certinfo` entry point and
# asserts the output is well-formed.
#
# This is the safety net for the x509-parser → in-tree-parser rewrite.
# A new parser bug that would have broken real-world certs shows up here
# as a failing assertion, not as silent breakage in production.

import re
from pathlib import Path

import pytest

from certmonitor import certinfo

FIXTURES = Path(__file__).parent / "fixtures" / "diff_corpus"
HEX_RE = re.compile(r"^[0-9a-f]*$")
# Standard RSA modulus sizes seen in the wild
ACCEPTABLE_RSA_BITS = {1024, 2048, 3072, 4096, 8192}
# Curve OIDs we expect to encounter on the public web
P256_OID = "1.2.840.10045.3.1.7"
P384_OID = "1.3.132.0.34"
P521_OID = "1.3.132.0.35"
KNOWN_CURVE_OIDS = {P256_OID, P384_OID, P521_OID}
# Sanity floor for cert validity timestamps (anything before 1990 is junk).
EARLIEST_REASONABLE_NOT_BEFORE = 631_152_000  # 1990-01-01


def _corpus():
    files = sorted(FIXTURES.glob("*.der"))
    if not files:
        pytest.skip("diff corpus not captured; run scripts to populate it")
    return files


CORPUS = _corpus()


@pytest.fixture(scope="module")
def parsed():
    """All corpus certs parsed via every public entry point.

    Returns a list of dicts, one per cert, each containing the outputs
    of `parse_public_key_info`, `extract_public_key_der`, `extract_public_key_pem`,
    plus the source filename. Module-scoped so we only parse once.
    """
    out = []
    for path in CORPUS:
        der = path.read_bytes()
        out.append(
            {
                "name": path.name,
                "der": der,
                "info": certinfo.parse_public_key_info(der),
                "spki_der": certinfo.extract_public_key_der(der),
                "spki_pem": certinfo.extract_public_key_pem(der),
            }
        )
    return out


class TestCorpusParses:
    def test_all_certs_parse(self, parsed):
        assert len(parsed) >= 100, (
            f"expected at least 100 corpus certs, got {len(parsed)}"
        )

    def test_all_have_recognized_algorithm(self, parsed):
        unrecognized = [
            p["name"]
            for p in parsed
            if p["info"]["algorithm"] not in {"rsaEncryption", "ecPublicKey"}
        ]
        assert not unrecognized, (
            f"unexpected key algorithms in {len(unrecognized)} certs: {unrecognized[:5]}"
        )


class TestPublicKeyInfo:
    def test_rsa_bit_lengths_are_canonical(self, parsed):
        rsa = [p for p in parsed if p["info"]["algorithm"] == "rsaEncryption"]
        assert rsa, "corpus has no RSA certs"
        bad = [
            (p["name"], p["info"]["size"])
            for p in rsa
            if p["info"]["size"] not in ACCEPTABLE_RSA_BITS
        ]
        assert not bad, (
            f"RSA bit lengths must be in {sorted(ACCEPTABLE_RSA_BITS)}; saw {bad[:5]}"
        )

    def test_rsa_curve_is_none(self, parsed):
        for p in parsed:
            if p["info"]["algorithm"] == "rsaEncryption":
                assert p["info"]["curve"] is None, p["name"]

    def test_ec_curve_is_actual_curve_oid(self, parsed):
        """Catches the original bug — `curve` must hold a curve OID, not
        the algorithm OID `1.2.840.10045.2.1`.
        """
        ec = [p for p in parsed if p["info"]["algorithm"] == "ecPublicKey"]
        assert ec, "corpus has no EC certs"
        for p in ec:
            curve = p["info"]["curve"]
            assert curve is not None, p["name"]
            assert curve != "1.2.840.10045.2.1", (
                f"{p['name']}: `curve` field contains the EC algorithm OID — bug regression"
            )
            assert curve in KNOWN_CURVE_OIDS, (
                f"{p['name']}: unexpected curve OID {curve!r}"
            )

    def test_ec_key_sizes(self, parsed):
        for p in parsed:
            if p["info"]["algorithm"] != "ecPublicKey":
                continue
            curve = p["info"]["curve"]
            size = p["info"]["size"]
            expected = {P256_OID: 256, P384_OID: 384, P521_OID: 521}[curve]
            assert size == expected, (
                f"{p['name']}: curve {curve} should yield size {expected}, got {size}"
            )


class TestSpkiBytes:
    def test_der_starts_with_sequence(self, parsed):
        for p in parsed:
            assert p["spki_der"][:1] == b"\x30", p["name"]

    def test_der_is_proper_subset_of_cert(self, parsed):
        for p in parsed:
            # SPKI bytes must appear inside the cert DER.
            assert p["spki_der"] in p["der"], p["name"]

    def test_pem_round_trip(self, parsed):
        import base64

        for p in parsed:
            pem = p["spki_pem"]
            assert pem.startswith("-----BEGIN PUBLIC KEY-----"), p["name"]
            assert pem.rstrip().endswith("-----END PUBLIC KEY-----"), p["name"]
            body = "".join(pem.splitlines()[1:-1])
            decoded = base64.b64decode(body)
            assert decoded == p["spki_der"], p["name"]


class TestAnalyzeChain:
    @pytest.fixture(scope="class")
    def analysis(self):
        chain = [
            (Path("tests/fixtures") / f"chain_{i}.der").read_bytes() for i in range(3)
        ]
        return certinfo.analyze_chain(chain)

    def test_chain_length(self, analysis):
        assert analysis["chain_length"] == 3

    def test_certs_per_position(self, analysis):
        assert len(analysis["certs"]) == 3
        for i, cert in enumerate(analysis["certs"]):
            assert cert["position"] == i

    def test_per_cert_field_shape(self, analysis):
        required = {
            "position",
            "subject",
            "issuer",
            "not_before_unix",
            "not_after_unix",
            "serial_number",
            "signature_algorithm_oid",
            "signature_algorithm_weak",
            "is_ca",
            "subject_key_identifier",
            "authority_key_identifier",
            "is_self_signed",
            "public_key_info",
        }
        for cert in analysis["certs"]:
            missing = required - set(cert.keys())
            assert not missing, missing

    def test_serial_is_lowercase_hex(self, analysis):
        for cert in analysis["certs"]:
            serial = cert["serial_number"]
            assert HEX_RE.match(serial), (cert["position"], serial)

    def test_validity_timestamps_sane(self, analysis):
        for cert in analysis["certs"]:
            assert cert["not_before_unix"] >= EARLIEST_REASONABLE_NOT_BEFORE
            assert cert["not_after_unix"] > cert["not_before_unix"]

    def test_ski_and_aki_are_hex_or_none(self, analysis):
        for cert in analysis["certs"]:
            for k in ("subject_key_identifier", "authority_key_identifier"):
                v = cert[k]
                if v is not None:
                    assert HEX_RE.match(v), (cert["position"], k, v)

    def test_ordering_and_links(self, analysis):
        # The captured chain is a real, well-ordered Google chain.
        assert analysis["ordered"] is True
        assert len(analysis["links"]) == 2
        for link in analysis["links"]:
            assert link["subject_matches_issuer"] is True


class TestCorpusValidityTimestamps:
    """Sanity-check timestamps across the entire corpus, not just the
    captured chain. Catches off-by-month/year bugs in time decoding."""

    def test_all_validity_periods_make_sense(self, parsed):
        # We don't have validity in the SPKI-only entry points, so re-run
        # analyze_chain on each cert as a single-element chain to access
        # the timestamps via the chain analyzer.
        for p in parsed:
            result = certinfo.analyze_chain([p["der"]])
            cert = result["certs"][0]
            nb = cert["not_before_unix"]
            na = cert["not_after_unix"]
            assert nb >= EARLIEST_REASONABLE_NOT_BEFORE, (p["name"], nb)
            assert na > nb, (p["name"], nb, na)
            # Validity span no more than 100 years (sanity floor for roots)
            assert na - nb < 100 * 365 * 24 * 3600, (p["name"], na - nb)

    def test_all_dn_fields_decoded(self, parsed):
        for p in parsed:
            result = certinfo.analyze_chain([p["der"]])
            cert = result["certs"][0]
            assert isinstance(cert["subject"], dict)
            assert isinstance(cert["issuer"], dict)
            # Every cert in the corpus should have at least a CN or O
            # in the subject — anything else would be very unusual.
            subj = cert["subject"]
            assert subj.get("commonName") or subj.get("organizationName"), (
                p["name"],
                subj,
            )
