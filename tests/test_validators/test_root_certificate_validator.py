import pytest
from certmonitor.validators.root_certificate_validator import RootCertificateValidator


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {
            "issuer": {"commonName": "Trusted CA"},
            "OCSP": ["https://ocsp.test"],
            "caIssuers": ["https://ca.test"],
        },
        {"issuer": {"commonName": "Untrusted CA"}},
    ],
)
def test_metadata_cannot_establish_trust(metadata):
    result = RootCertificateValidator().validate(
        {"cert_info": metadata}, "example.com", 443
    )
    assert result["is_valid"] is False
    assert result["status"] == "error"
    assert result["error"] == "TrustNotVerified"


@pytest.mark.parametrize(
    "valid,status", [(True, "pass"), (False, "fail"), (False, "error")]
)
def test_reports_verification_evidence(valid, status):
    evidence = {"is_valid": valid, "status": status, "trust_verified": valid}
    if not valid:
        evidence["reason"] = "Verification failed"
    result = RootCertificateValidator().validate(evidence, "example.com", 443)
    assert all(result[key] == value for key, value in evidence.items())
    assert result["issuer"] == {}
    assert result["warnings"] == []
