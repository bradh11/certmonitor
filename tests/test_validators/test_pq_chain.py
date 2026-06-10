# tests/test_validators/test_pq_chain.py

import pytest

from certmonitor.validators.pq_chain import PqChainValidator

ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"
COMPOSITE_OID = "1.3.6.1.5.5.7.6.45"  # id-MLDSA65-ECDSA-P256-SHA512


def cert_entry(key_alg, sig_oid, self_signed=False, cn="example"):
    return {
        "subject": {"commonName": cn},
        "public_key_info": {"algorithm": key_alg, "size": 2048},
        "signature_algorithm_oid": sig_oid,
        "is_self_signed": self_signed,
    }


def chain(*entries):
    return {"chain_analysis": {"certs": list(entries)}}


class TestPqChainValidator:
    def setup_method(self):
        self.v = PqChainValidator()

    def test_name_and_registration(self):
        from certmonitor.config import DEFAULT_VALIDATORS
        from certmonitor.validators import VALIDATORS

        assert self.v.name == "pq_chain"
        assert "pq_chain" in VALIDATORS
        assert "pq_chain" not in DEFAULT_VALIDATORS

    def test_all_classical_chain(self):
        cert = chain(
            cert_entry("rsaEncryption", SHA256_RSA_OID, cn="leaf"),
            cert_entry("rsaEncryption", SHA256_RSA_OID, cn="inter"),
            cert_entry("rsaEncryption", SHA256_RSA_OID, self_signed=True, cn="root"),
        )
        r = self.v.validate(cert, "h", 443)
        assert r["chain_length"] == 3
        assert [link["role"] for link in r["links"]] == ["leaf", "intermediate", "root"]
        assert all(link["is_pq"] is False for link in r["links"])
        assert r["summary"] == {
            "leaf_pq": False,
            "intermediate_pq": False,
            "root_pq": False,
        }
        assert r["is_valid"] is False
        assert "not post-quantum" in r["reason"]

    def test_hybrid_migration_pq_leaf_classical_rest(self):
        cert = chain(
            cert_entry("ml-dsa-65", SHA256_RSA_OID, cn="leaf"),
            cert_entry("rsaEncryption", SHA256_RSA_OID, cn="inter"),
            cert_entry("rsaEncryption", SHA256_RSA_OID, self_signed=True, cn="root"),
        )
        r = self.v.validate(cert, "h", 443)
        # The realistic migration shape: PQ leaf, classical chain above.
        assert r["links"][0]["key_is_pq"] is True
        assert r["links"][0]["signature_is_pq"] is False  # CA's choice
        assert r["summary"]["leaf_pq"] is True
        assert r["summary"]["intermediate_pq"] is False
        assert r["summary"]["root_pq"] is False
        assert r["is_valid"] is True  # leaf key decides by default

    def test_fully_pq_chain(self):
        cert = chain(
            cert_entry("ml-dsa-65", ML_DSA_65_OID, cn="leaf"),
            cert_entry("ml-dsa-87", ML_DSA_65_OID, cn="inter"),
            cert_entry("ml-dsa-87", ML_DSA_65_OID, self_signed=True, cn="root"),
        )
        r = self.v.validate(cert, "h", 443)
        assert all(link["is_pq"] for link in r["links"])
        assert r["summary"] == {
            "leaf_pq": True,
            "intermediate_pq": True,
            "root_pq": True,
        }
        assert r["is_valid"] is True

    def test_require_full_chain_user_arg(self):
        mixed = chain(
            cert_entry("ml-dsa-65", SHA256_RSA_OID, cn="leaf"),
            cert_entry("rsaEncryption", SHA256_RSA_OID, self_signed=True, cn="root"),
        )
        assert self.v.validate(mixed, "h", 443)["is_valid"] is True
        strict = self.v.validate(mixed, "h", 443, require_full_chain=True)
        assert strict["is_valid"] is False
        assert "every certificate" in strict["reason"]

    def test_composite_signature_counts_as_pq(self):
        # Classical key, composite (PQ+classical) signature: a migration
        # signal from the issuing CA — the cert counts as PQ even though
        # the key alone does not.
        cert = chain(cert_entry("ecPublicKey", COMPOSITE_OID, self_signed=True))
        r = self.v.validate(cert, "h", 443)
        link = r["links"][0]
        assert link["key_is_pq"] is False
        assert link["signature_is_pq"] is True
        assert link["is_pq"] is True
        # ...but the default verdict tracks the leaf KEY, which is classical.
        assert r["is_valid"] is False

    def test_single_self_signed_cert(self):
        cert = chain(cert_entry("ml-dsa-44", ML_DSA_65_OID, self_signed=True))
        r = self.v.validate(cert, "h", 443)
        assert r["chain_length"] == 1
        assert r["links"][0]["role"] == "leaf"
        assert r["summary"] == {
            "leaf_pq": True,
            "intermediate_pq": None,  # no certs in these roles
            "root_pq": None,
        }
        assert r["is_valid"] is True

    def test_empty_chain_returns_error(self):
        r = self.v.validate({"chain_analysis": {"certs": []}}, "h", 443)
        assert r["is_valid"] is False
        assert "empty" in r["reason"]
        assert r["chain_length"] == 0

    def test_chain_error_passthrough(self):
        r = self.v.validate({"chain_error": "boom"}, "h", 443)
        assert r["is_valid"] is False
        assert r["reason"] == "boom"

    def test_missing_chain_analysis_old_interpreter(self):
        # Python 3.8/3.9: the SSL handler cannot retrieve the chain.
        r = self.v.validate({"cert_info": {}}, "h", 443)
        assert r["is_valid"] is False
        assert "3.10" in r["reason"]

    def test_analysis_error_dict(self):
        r = self.v.validate({"chain_analysis": {"error": "parse failed"}}, "h", 443)
        assert r["is_valid"] is False
        assert r["reason"] == "parse failed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
