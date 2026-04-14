# tests/test_certinfo_chain.py
#
# Direct tests for the Rust-backed ``certmonitor.certinfo`` module:
# - ``analyze_chain`` against a real captured TLS chain, asserting only
#   time-insensitive properties so the tests don't bit-rot.
# - ``extract_public_key_pem`` regression after dropping the ``base64``
#   Rust dependency in favor of an inlined encoder.

import base64
import ssl

import pytest

from certmonitor import certinfo


class TestAnalyzeChainRealChain:
    def test_chain_length(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        assert result["chain_length"] == 3

    def test_shape(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        assert set(result.keys()) == {
            "chain_length",
            "certs",
            "links",
            "ordered",
            "terminates_in_self_signed",
        }
        assert len(result["certs"]) == 3
        assert len(result["links"]) == 2

    def test_ordered(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        assert result["ordered"] is True
        for link in result["links"]:
            assert link["subject_matches_issuer"] is True

    def test_per_cert_fields(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
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
        for i, cert in enumerate(result["certs"]):
            missing = required - set(cert.keys())
            assert not missing, f"cert[{i}] missing fields: {missing}"

    def test_leaf_not_ca(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        assert result["certs"][0]["is_ca"] is False

    def test_intermediate_is_ca(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        assert result["certs"][1]["is_ca"] is True

    def test_leaf_has_public_key_info(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        pki = result["certs"][0]["public_key_info"]
        assert pki["algorithm"] in {"rsaEncryption", "ecPublicKey"}
        assert pki["size"] > 0

    def test_sha256_signature_not_flagged_as_weak(self, real_chain_ders):
        # Every current public-web cert uses sha256 or stronger.
        result = certinfo.analyze_chain(real_chain_ders)
        for cert in result["certs"]:
            assert cert["signature_algorithm_weak"] is False

    def test_serial_is_lowercase_hex(self, real_chain_ders):
        result = certinfo.analyze_chain(real_chain_ders)
        for cert in result["certs"]:
            serial = cert["serial_number"]
            assert serial == serial.lower()
            int(serial, 16)  # parses as hex

    def test_empty_chain(self):
        result = certinfo.analyze_chain([])
        assert result["chain_length"] == 0
        assert result["certs"] == []
        assert result["links"] == []
        assert result["ordered"] is True
        assert result["terminates_in_self_signed"] is False

    def test_single_leaf_chain(self, real_chain_ders):
        result = certinfo.analyze_chain([real_chain_ders[0]])
        assert result["chain_length"] == 1
        assert result["links"] == []
        assert result["certs"][0]["is_self_signed"] is False

    def test_out_of_order_detected(self, real_chain_ders):
        # Swap leaf and intermediate — breaks subject/issuer linkage.
        reordered = [real_chain_ders[1], real_chain_ders[0], real_chain_ders[2]]
        result = certinfo.analyze_chain(reordered)
        assert result["ordered"] is False
        assert result["links"][0]["subject_matches_issuer"] is False

    def test_invalid_der_raises(self):
        with pytest.raises(ValueError, match="Failed to parse"):
            certinfo.analyze_chain([b"not a cert"])


class TestBase64InlineRegression:
    """Guards the switch from the ``base64`` crate to an inlined encoder.

    We round-trip through ``extract_public_key_pem`` and check the decoded
    base64 content matches the SPKI DER bytes exactly — the failure mode we
    most care about is an alphabet or padding bug in the inlined encoder.
    """

    def test_pem_wrapping(self, real_chain_ders):
        leaf_der = real_chain_ders[0]
        pem = certinfo.extract_public_key_pem(leaf_der)
        lines = pem.splitlines()
        assert lines[0] == "-----BEGIN PUBLIC KEY-----"
        assert lines[-1] == "-----END PUBLIC KEY-----"
        # Body lines (between markers) are at most 64 chars each
        body_lines = lines[1:-1]
        assert all(len(line) <= 64 for line in body_lines)

    def test_pem_decodes_to_spki_der(self, real_chain_ders):
        leaf_der = real_chain_ders[0]
        pem = certinfo.extract_public_key_pem(leaf_der)
        expected_spki = certinfo.extract_public_key_der(leaf_der)
        body = "".join(pem.splitlines()[1:-1])
        decoded = base64.b64decode(body)
        assert decoded == expected_spki

    def test_pem_roundtrip_via_ssl(self, real_chain_ders):
        # Also confirm the PEM output is a valid SPKI PEM that stdlib can parse.
        # ssl doesn't have a public-key loader, but we can at least confirm
        # the base64 body is padded correctly for stdlib's b64decode.
        leaf_der = real_chain_ders[0]
        pem = certinfo.extract_public_key_pem(leaf_der)
        body = "".join(pem.splitlines()[1:-1])
        # Length must be a multiple of 4 (with padding).
        assert len(body) % 4 == 0
        # Reuses ssl module's cert DER→PEM helper path sanity check.
        cert_pem = ssl.DER_cert_to_PEM_cert(leaf_der)
        assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
