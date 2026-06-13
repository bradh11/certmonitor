# tests/test_real_cert_validation.py

"""Integration guardrail against validator/parser contract drift.

The EC-curve bug (#48) and the TLS 1.3 cipher bug (#50) shared one root
cause: a validator's hardcoded expectations drifted from what the Rust
parser / a real handshake actually produces, while the unit tests asserted
the stale assumption (they fed hand-built dicts instead of real output).

These tests close that gap for the certificate validators by driving them
with the *real* Rust parser output from captured certificate DER, assembled
the same way ``CertMonitor._fetch_raw_cert`` assembles ``cert_data``. A
membership check or field-shape that drifts from the parser will fail here
even when the mock-based unit tests still pass.
"""

from pathlib import Path

import pytest

from certmonitor import certinfo
from certmonitor.validators import VALIDATORS

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def real_cert_data():
    """Build ``cert_data`` from the captured chain fixtures using the real
    Rust parser, mirroring how core.py assembles it for validators."""
    chain_ders = [(_FIXTURES / f"chain_{i}.der").read_bytes() for i in range(3)]
    leaf = chain_ders[0]
    return {
        "public_key_info": certinfo.parse_public_key_info(leaf),
        "chain_analysis": certinfo.analyze_chain(chain_ders),
        "chain_error": None,
    }


class TestRealCertValidators:
    """Cert validators must produce sane results on real parser output."""

    def test_key_info_accepts_real_ec_leaf(self, real_cert_data):
        """The captured leaf is a real P-256 cert, so it must validate strong.

        This is the exact path the #48 EC-curve bug broke: the parser emits
        the curve and key_info judges it.
        """
        result = VALIDATORS["key_info"].validate(real_cert_data, "example.com", 443)
        assert result["key_type"] == "ecPublicKey"
        assert result["curve"] == "secp256r1"
        assert result["is_valid"] is True

    def test_chain_validator_runs_clean(self, real_cert_data):
        """The chain validator must consume real analyze_chain output without
        producing a structured error."""
        result = VALIDATORS["chain"].validate(real_cert_data, "example.com", 443)
        assert "error" not in result
        assert "is_valid" in result

    def test_pq_signature_runs_clean(self, real_cert_data):
        """pq_signature must interpret real output; the classical leaf is not PQ."""
        result = VALIDATORS["pq_signature"].validate(real_cert_data, "example.com", 443)
        assert "error" not in result
        assert result["is_pq"] is False  # EC/RSA fixtures are classical

    def test_pq_chain_runs_clean(self, real_cert_data):
        """pq_chain must interpret real output; its per-chain summary is classical."""
        result = VALIDATORS["pq_chain"].validate(real_cert_data, "example.com", 443)
        assert "error" not in result
        assert result["summary"] == {
            "leaf_pq": False,
            "intermediate_pq": False,
            "root_pq": False,
        }


class TestAllowedCipherSuitesAreRealistic:
    """The weak_cipher default allow-list must cover what modern handshakes
    negotiate.

    Guards the #50 class: tls_version permits TLS 1.3, so the suites a TLS 1.3
    handshake actually uses must be allowed. Also checks the full Mozilla
    "Intermediate" set is present (the DHE-RSA suites were once missing).
    """

    def test_mozilla_intermediate_suites_present_in_default(self):
        from certmonitor.validators.weak_cipher import _DEFAULT_ALLOWED_CIPHER_SUITES

        expected = {
            # TLS 1.3
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            # TLS 1.2 ECDHE
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            # TLS 1.2 DHE
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-CHACHA20-POLY1305",
        }
        missing = expected - _DEFAULT_ALLOWED_CIPHER_SUITES
        assert not missing, f"Mozilla Intermediate suites missing: {missing}"


if __name__ == "__main__":
    pytest.main([__file__])
