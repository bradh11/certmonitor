# tests/test_validators/test_chain.py

import datetime
from typing import Any, Dict

import pytest

from certmonitor.validators import VALIDATORS
from certmonitor.validators.chain import ChainValidator


@pytest.fixture
def validator():
    return ChainValidator()


def _wrap(analysis: Dict[str, Any], chain_error=None) -> Dict[str, Any]:
    return {
        "cert_info": {},
        "chain_analysis": analysis,
        "chain_error": chain_error,
    }


class TestRegistrationAndIntrospection:
    def test_validator_registered(self):
        assert "chain" in VALIDATORS
        assert isinstance(VALIDATORS["chain"], ChainValidator)

    def test_not_default_enabled(self):
        from certmonitor.config import DEFAULT_VALIDATORS

        assert "chain" not in DEFAULT_VALIDATORS

    def test_validator_type_is_cert(self, validator):
        assert validator.validator_type == "cert"

    def test_user_param_names(self, validator):
        assert validator._user_param_names == frozenset(
            {
                "min_chain_length",
                "require_root_in_chain",
                "allow_self_signed_leaf",
                "weak_signature_algorithms",
            }
        )


class TestHappyPath:
    def test_healthy_chain_is_valid(self, validator, healthy_chain_analysis):
        result = validator.validate(_wrap(healthy_chain_analysis), "host", 443)
        assert result["is_valid"] is True
        assert result["chain_length"] == 3
        assert result["chain_ordered"] is True
        assert result["terminates_in_self_signed"] is True
        assert len(result["certs"]) == 3
        assert result["certs"][0]["role"] == "leaf"
        assert result["certs"][1]["role"] == "intermediate"
        assert result["certs"][2]["role"] == "root"
        assert all(c["warnings"] == [] for c in result["certs"])
        assert "reason" not in result

    def test_days_to_expiry_populated(self, validator, healthy_chain_analysis):
        result = validator.validate(_wrap(healthy_chain_analysis), "host", 443)
        # Leaf was built with now+60 days
        assert 58 <= result["certs"][0]["days_to_expiry"] <= 61


class TestChainLength:
    def test_length_one_fails_by_default(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="solo.example.com",
            issuer_cn="Some CA",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        analysis = build_chain_analysis([leaf])
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is False
        assert "below the required minimum" in result["reason"]
        assert result["chain_length"] == 1

    def test_length_one_passes_with_min_chain_length_1(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="solo.example.com",
            issuer_cn="Some CA",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        analysis = build_chain_analysis([leaf])
        result = validator.validate(_wrap(analysis), "host", 443, min_chain_length=1)
        assert result["is_valid"] is True


class TestRootRequirement:
    def test_missing_root_passes_by_default_with_warning(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="Intermediate CA",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        intermediate = synthetic_cert(
            position=1,
            subject_cn="Intermediate CA",
            issuer_cn="Offline Root",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
        )
        analysis = build_chain_analysis([leaf, intermediate])
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is True
        assert any("does not terminate" in w for w in result["warnings"])

    def test_missing_root_fails_when_required(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="Intermediate CA",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        intermediate = synthetic_cert(
            position=1,
            subject_cn="Intermediate CA",
            issuer_cn="Offline Root",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
        )
        analysis = build_chain_analysis([leaf, intermediate])
        result = validator.validate(
            _wrap(analysis), "host", 443, require_root_in_chain=True
        )
        assert result["is_valid"] is False
        assert any("require_root_in_chain=True" in w for w in result["warnings"])


class TestOrdering:
    def test_out_of_order_detected(self, validator, healthy_chain_analysis):
        # Swap intermediate and root so subject/issuer linkage breaks.
        analysis = healthy_chain_analysis
        analysis["certs"][1], analysis["certs"][2] = (
            analysis["certs"][2],
            analysis["certs"][1],
        )
        # Manually flip the flag the way the Rust side would
        analysis["ordered"] = False
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is False
        assert result["chain_ordered"] is False
        assert any("not ordered correctly" in w for w in result["warnings"])


class TestExpiration:
    def test_expired_intermediate_fails(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        intermediate = synthetic_cert(
            position=1,
            subject_cn="CA",
            issuer_cn="Root",
            not_before=now - 10 * 365 * 24 * 3600,
            not_after=now - 24 * 3600,  # expired yesterday
            is_ca=True,
        )
        root = synthetic_cert(
            position=2,
            subject_cn="Root",
            issuer_cn="Root",
            not_before=now - 20 * 365 * 24 * 3600,
            not_after=now + 5 * 365 * 24 * 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([leaf, intermediate, root])
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is False
        # The expired intermediate has its own warning
        inter_report = result["certs"][1]
        assert any("expired" in w for w in inter_report["warnings"])

    def test_not_yet_valid(self, validator, synthetic_cert, build_chain_analysis):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        future_leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="CA",
            not_before=now + 24 * 3600,  # starts tomorrow
            not_after=now + 365 * 24 * 3600,
        )
        ca = synthetic_cert(
            position=1,
            subject_cn="CA",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([future_leaf, ca])
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is False
        assert any("not yet valid" in w for w in result["warnings"])


class TestSignatureAlgorithm:
    def test_sha1_warns_but_valid(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            sig_oid="1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
        )
        ca = synthetic_cert(
            position=1,
            subject_cn="CA",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([leaf, ca])
        result = validator.validate(_wrap(analysis), "host", 443)
        assert result["is_valid"] is True
        assert any("weak signature algorithm" in w for w in result["warnings"])

    def test_override_weak_set_to_flag_sha256(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            sig_oid="1.2.840.113549.1.1.11",  # sha256
        )
        ca = synthetic_cert(
            position=1,
            subject_cn="CA",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([leaf, ca])
        result = validator.validate(
            _wrap(analysis),
            "host",
            443,
            weak_signature_algorithms=["1.2.840.113549.1.1.11"],
        )
        assert result["is_valid"] is True
        assert any("weak signature algorithm" in w for w in result["warnings"])

    def test_empty_weak_set_disables_check(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            sig_oid="1.2.840.113549.1.1.5",  # sha1
        )
        ca = synthetic_cert(
            position=1,
            subject_cn="CA",
            issuer_cn="CA",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([leaf, ca])
        result = validator.validate(
            _wrap(analysis), "host", 443, weak_signature_algorithms=[]
        )
        assert not any("weak signature algorithm" in w for w in result["warnings"])


class TestSelfSignedLeaf:
    def _make(self, synthetic_cert, build_chain_analysis):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="self.example.com",
            issuer_cn="self.example.com",
            not_before=now - 3600,
            not_after=now + 3600,
            is_self_signed=True,
        )
        return build_chain_analysis([leaf])

    def test_rejected_by_default(self, validator, synthetic_cert, build_chain_analysis):
        analysis = self._make(synthetic_cert, build_chain_analysis)
        result = validator.validate(_wrap(analysis), "host", 443, min_chain_length=1)
        assert result["is_valid"] is False
        assert any("self-signed" in w for w in result["warnings"])

    def test_allowed_with_flag(self, validator, synthetic_cert, build_chain_analysis):
        analysis = self._make(synthetic_cert, build_chain_analysis)
        result = validator.validate(
            _wrap(analysis),
            "host",
            443,
            min_chain_length=1,
            allow_self_signed_leaf=True,
        )
        assert result["is_valid"] is True


class TestNonCaIntermediate:
    def test_non_ca_intermediate_warns(
        self, validator, synthetic_cert, build_chain_analysis
    ):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        leaf = synthetic_cert(
            position=0,
            subject_cn="leaf",
            issuer_cn="Bogus Intermediate",
            not_before=now - 3600,
            not_after=now + 3600,
        )
        # Intermediate missing is_ca=True (simulating a misconfiguration).
        inter = synthetic_cert(
            position=1,
            subject_cn="Bogus Intermediate",
            issuer_cn="Root",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=False,
        )
        root = synthetic_cert(
            position=2,
            subject_cn="Root",
            issuer_cn="Root",
            not_before=now - 3600,
            not_after=now + 3600,
            is_ca=True,
            is_self_signed=True,
        )
        analysis = build_chain_analysis([leaf, inter, root])
        result = validator.validate(_wrap(analysis), "host", 443)
        # Chain still passes (non-blocking warning), but the warning surfaces.
        assert any("not marked as a CA" in w for w in result["warnings"])


class TestErrorPaths:
    def test_chain_error_propagates(self, validator):
        cert = {
            "cert_info": {},
            "chain_analysis": None,
            "chain_error": "Certificate chain retrieval requires Python 3.10 or newer",
        }
        result = validator.validate(cert, "host", 443)
        assert result["is_valid"] is False
        assert "Python 3.10" in result["reason"]
        assert result["chain_length"] == 0
        assert result["certs"] == []

    def test_missing_chain_analysis(self, validator):
        cert = {"cert_info": {}, "chain_analysis": None, "chain_error": None}
        result = validator.validate(cert, "host", 443)
        assert result["is_valid"] is False
        assert "was not fetched" in result["reason"]

    def test_chain_analysis_error_dict(self, validator):
        cert = {
            "cert_info": {},
            "chain_analysis": {"error": "analyze_chain blew up"},
            "chain_error": None,
        }
        result = validator.validate(cert, "host", 443)
        assert result["is_valid"] is False
        assert "analyze_chain blew up" in result["reason"]
