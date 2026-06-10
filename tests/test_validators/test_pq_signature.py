# tests/test_validators/test_pq_signature.py

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from certmonitor.core import CertMonitor
from certmonitor.validators.pq_signature import PqSignatureValidator

ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"
COMPOSITE_OID = "1.3.6.1.5.5.7.6.45"  # id-MLDSA65-ECDSA-P256-SHA512


def leaf(key_alg, sig_oid, source="chain_analysis"):
    return {
        source: {
            "certs": [
                {
                    "subject": {"commonName": "leaf"},
                    "public_key_info": {"algorithm": key_alg, "size": 2048},
                    "signature_algorithm_oid": sig_oid,
                }
            ]
        }
    }


class TestPqSignatureValidator:
    def setup_method(self):
        self.v = PqSignatureValidator()

    def test_name_and_registration(self):
        from certmonitor.config import DEFAULT_VALIDATORS
        from certmonitor.validators import VALIDATORS

        assert self.v.name == "pq_signature"
        assert "pq_signature" in VALIDATORS
        assert "pq_signature" not in DEFAULT_VALIDATORS

    def test_pure_pq_leaf(self):
        r = self.v.validate(leaf("ml-dsa-65", ML_DSA_65_OID), "h", 443)
        assert r == {
            "key_algorithm": "ml-dsa-65",
            "key_is_pq": True,
            "signature_algorithm_oid": ML_DSA_65_OID,
            "signature_is_pq": True,
            "is_hybrid_composite": False,
            "is_pq": True,
            "is_valid": True,
        }

    def test_hybrid_composite_leaf(self):
        r = self.v.validate(leaf("mldsa65-ecdsa-p256-sha512", COMPOSITE_OID), "h", 443)
        assert r["key_is_pq"] is True
        assert r["signature_is_pq"] is True
        assert r["is_hybrid_composite"] is True
        assert r["is_valid"] is True

    def test_classical_leaf(self):
        r = self.v.validate(leaf("rsaEncryption", SHA256_RSA_OID), "h", 443)
        assert r["key_is_pq"] is False
        assert r["signature_is_pq"] is False
        assert r["is_hybrid_composite"] is False
        assert r["is_pq"] is False
        assert r["is_valid"] is False
        assert "not post-quantum" in r["reason"]

    def test_pq_key_classical_signature_default_valid(self):
        # The realistic migration shape: operator rotated the key, the
        # CA still signs classically. Leaf key decides by default —
        # consistent with pq_chain.
        r = self.v.validate(leaf("ml-dsa-65", SHA256_RSA_OID), "h", 443)
        assert r["key_is_pq"] is True
        assert r["signature_is_pq"] is False
        assert r["is_pq"] is True
        assert r["is_valid"] is True

    def test_pq_key_classical_signature_strict_mode(self):
        r = self.v.validate(
            leaf("ml-dsa-65", SHA256_RSA_OID),
            "h",
            443,
            require_pq_signature=True,
        )
        assert r["is_valid"] is False
        assert "require_pq_signature" in r["reason"]

    def test_classical_key_pq_signature_default_invalid(self):
        # Reverse migration shape: composite-signed but classical key.
        # is_pq reports the signal, but the verdict tracks the key.
        r = self.v.validate(leaf("ecPublicKey", COMPOSITE_OID), "h", 443)
        assert r["signature_is_pq"] is True
        assert r["is_hybrid_composite"] is True
        assert r["is_pq"] is True
        assert r["is_valid"] is False

    def test_unknown_algorithm_is_invalid_with_reason(self):
        r = self.v.validate(leaf("unknown", SHA256_RSA_OID), "h", 443)
        assert r["is_valid"] is False
        assert "unknown" in r["reason"]

    def test_leaf_analysis_fallback_used(self):
        # No chain_analysis (e.g. Python 3.8/3.9): the leaf-only
        # fallback supplies the same data and the validator works.
        r = self.v.validate(
            leaf("ml-dsa-65", ML_DSA_65_OID, source="leaf_analysis"), "h", 443
        )
        assert r["is_valid"] is True

    def test_chain_analysis_preferred_over_fallback(self):
        cert = leaf("ml-dsa-65", ML_DSA_65_OID)
        cert.update(leaf("rsaEncryption", SHA256_RSA_OID, source="leaf_analysis"))
        r = self.v.validate(cert, "h", 443)
        assert r["key_algorithm"] == "ml-dsa-65"  # chain_analysis won

    def test_errored_chain_falls_back_to_leaf_analysis(self):
        cert = {"chain_analysis": {"error": "boom"}}
        cert.update(leaf("ml-dsa-65", ML_DSA_65_OID, source="leaf_analysis"))
        r = self.v.validate(cert, "h", 443)
        assert r["is_valid"] is True

    def test_no_data_anywhere_returns_structured_error(self):
        r = self.v.validate({"cert_info": {}}, "h", 443)
        assert r["is_valid"] is False
        assert "could not be analyzed" in r["reason"]


class TestLeafAnalysisFallbackSource:
    """core._fetch_raw_cert populates leaf_analysis from the leaf DER
    when the chain is unavailable."""

    def _run_fetch(self, handler_payload):
        monitor = CertMonitor("example.com")
        handler = MagicMock()
        handler.fetch_raw_cert.return_value = handler_payload
        monitor.handler = handler
        monitor.connected = True
        with patch.object(monitor, "_ensure_connection", return_value=None):
            return monitor._fetch_raw_cert()

    def test_leaf_analysis_populated_when_chain_missing(self):
        der = (Path("tests/fixtures") / "chain_0.der").read_bytes()
        cert_data = self._run_fetch(
            {"cert_info": {"subject": {}}, "der": der, "pem": None}
        )
        assert cert_data.get("chain_analysis") is None
        la = cert_data["leaf_analysis"]
        assert la["chain_length"] == 1
        assert la["certs"][0]["signature_algorithm_oid"]
        assert la["certs"][0]["public_key_info"]["algorithm"]

    def test_no_leaf_analysis_when_chain_present(self):
        ders = [
            (Path("tests/fixtures") / f"chain_{i}.der").read_bytes() for i in range(3)
        ]
        cert_data = self._run_fetch(
            {
                "cert_info": {"subject": {}},
                "der": ders[0],
                "pem": None,
                "chain_der": ders,
            }
        )
        assert cert_data["chain_analysis"]["chain_length"] == 3
        assert "leaf_analysis" not in cert_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
