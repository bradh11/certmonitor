# tests/test_validators/test_root_certificate_validator.py

import pytest

from certmonitor.validators.root_certificate_validator import RootCertificateValidator


class TestRootCertificateValidator:
    """Test the RootCertificateValidator class."""

    def test_validator_name(self):
        """Test that the validator has the correct name."""
        validator = RootCertificateValidator()
        assert validator.name == "root_certificate"

    def test_validator_type(self):
        """Test that the validator has the correct type."""
        validator = RootCertificateValidator()
        assert validator.validator_type == "cert"

    def test_trusted_certificate(self):
        """Test validation with a trusted certificate (has OCSP, caIssuers, not self-signed, trusted CA)."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.digicert.com"],
                "caIssuers": ["http://cacerts.digicert.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is True
        assert (
            result["issuer"]["commonName"]
            == "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
        )
        assert result["issuer"]["organizationName"] == "DigiCert Inc"
        assert len(result["warnings"]) == 0

    def test_self_signed_certificate(self):
        """Test validation with a self-signed certificate."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "Self-Signed CA",
                    "organizationName": "Self-Signed Org",
                },
                "subject": {
                    "commonName": "Self-Signed CA",  # Same as issuer
                    "organizationName": "Self-Signed Org",
                },
                "OCSP": ["http://ocsp.selfsigned.com"],
                "caIssuers": ["http://cacerts.selfsigned.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert "Certificate is self-signed." in result["warnings"]

    def test_missing_ocsp(self):
        """Test validation when OCSP information is missing."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "caIssuers": ["http://cacerts.digicert.com/ca.crt"],
                # Missing OCSP
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert "Certificate does not provide OCSP information." in result["warnings"]

    def test_missing_ca_issuers(self):
        """Test validation when caIssuers information is missing."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.digicert.com"],
                # Missing caIssuers
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert (
            "Certificate does not provide caIssuers information." in result["warnings"]
        )

    def test_empty_ocsp(self):
        """Test validation when OCSP is empty."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": [],  # Empty list
                "caIssuers": ["http://cacerts.digicert.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert "Certificate does not provide OCSP information." in result["warnings"]

    def test_empty_ca_issuers(self):
        """Test validation when caIssuers is empty."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.digicert.com"],
                "caIssuers": [],  # Empty list
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert (
            "Certificate does not provide caIssuers information." in result["warnings"]
        )

    def test_untrusted_ca_common_name(self):
        """Test validation when CA common name contains 'untrusted'."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "Untrusted Root CA",
                    "organizationName": "Untrusted Corp",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.untrusted.com"],
                "caIssuers": ["http://cacerts.untrusted.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_untrusted_ca_organization_name(self):
        """Test validation when CA organization name contains 'untrusted'."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "Root CA",
                    "organizationName": "Untrusted Organization",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.example.com"],
                "caIssuers": ["http://cacerts.example.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_missing_issuer_info(self):
        """Test validation when issuer information is missing entirely."""
        cert = {
            "cert_info": {
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.example.com"],
                "caIssuers": ["http://cacerts.example.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        # A certificate without issuer information should be considered invalid
        assert result["is_valid"] is False
        assert result["issuer"] == {}
        assert (
            "Certificate does not have valid issuer information." in result["warnings"]
        )
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_missing_subject_info(self):
        """Test validation when subject information is missing."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA",
                    "organizationName": "DigiCert Inc",
                },
                "OCSP": ["http://ocsp.digicert.com"],
                "caIssuers": ["http://cacerts.digicert.com/ca.crt"],
                # Missing subject
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        # Missing subject doesn't make it self-signed, so this could be valid
        # depending on other criteria
        assert result["is_valid"] is True

    def test_missing_cert_info(self):
        """Test validation when cert_info is missing entirely."""
        cert = {}
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert result["issuer"] == {}
        assert (
            "Certificate does not have valid issuer information." in result["warnings"]
        )
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_multiple_warnings(self):
        """Test that multiple warnings are collected properly."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "Untrusted CA",
                    "organizationName": "Untrusted Org",
                },
                "subject": {
                    "commonName": "Untrusted CA",  # Same as issuer (self-signed)
                    "organizationName": "Untrusted Org",
                },
                # Missing OCSP and caIssuers
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert (
            len(result["warnings"]) == 4
        )  # OCSP, caIssuers, self-signed, untrusted CA
        assert "Certificate does not provide OCSP information." in result["warnings"]
        assert (
            "Certificate does not provide caIssuers information." in result["warnings"]
        )
        assert "Certificate is self-signed." in result["warnings"]
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_case_insensitive_untrusted_detection(self):
        """Test that untrusted detection is case-insensitive."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "UNTRUSTED Root CA",
                    "organizationName": "DigiCert Inc",
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.example.com"],
                "caIssuers": ["http://cacerts.example.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is False
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )

    def test_partial_issuer_info(self):
        """Test validation with partial issuer information."""
        cert = {
            "cert_info": {
                "issuer": {
                    "commonName": "DigiCert CA"
                    # Missing organizationName
                },
                "subject": {
                    "commonName": "www.example.com",
                    "organizationName": "Example Corp",
                },
                "OCSP": ["http://ocsp.digicert.com"],
                "caIssuers": ["http://cacerts.digicert.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["is_valid"] is True
        assert result["issuer"]["commonName"] == "DigiCert CA"
        # organizationName should default to "Unknown" when missing
        assert result["issuer"].get("organizationName") is None  # It's just not present

    def test_empty_issuer_subject(self):
        """Test validation with empty issuer and subject dictionaries."""
        cert = {
            "cert_info": {
                "issuer": {},
                "subject": {},
                "OCSP": ["http://ocsp.example.com"],
                "caIssuers": ["http://cacerts.example.com/ca.crt"],
            }
        }
        validator = RootCertificateValidator()
        result = validator.validate(cert, "example.com", 443)

        # Empty issuer should be considered invalid (missing valid issuer info)
        # Empty issuer and subject are equal, so this is also considered self-signed
        assert result["is_valid"] is False
        assert (
            "Certificate does not have valid issuer information." in result["warnings"]
        )
        assert "Certificate is self-signed." in result["warnings"]
        assert any(
            "untrusted root ca" in warning.lower() for warning in result["warnings"]
        )


if __name__ == "__main__":
    pytest.main([__file__])
