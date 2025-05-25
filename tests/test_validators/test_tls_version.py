# tests/test_validators/test_tls_version.py

import pytest
from unittest.mock import patch

from certmonitor.validators.tls_version import TLSVersionValidator


class TestTLSVersionValidator:
    """Test the TLSVersionValidator class."""

    def test_validator_name(self):
        """Test that the validator has the correct name."""
        validator = TLSVersionValidator()
        assert validator.name == "tls_version"

    def test_validator_type(self):
        """Test that the validator has the correct type."""
        validator = TLSVersionValidator()
        assert validator.validator_type == "cipher"

    def test_allowed_tls_version_1_3(self):
        """Test validation with TLSv1.3 (should be allowed)."""
        cipher_info = {"protocol_version": "TLSv1.3"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["protocol_version"] == "TLSv1.3"
        assert "reason" not in result

    def test_allowed_tls_version_1_2(self):
        """Test validation with TLSv1.2 (should be allowed)."""
        cipher_info = {"protocol_version": "TLSv1.2"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["protocol_version"] == "TLSv1.2"
        assert "reason" not in result

    def test_disallowed_tls_version_1_1(self):
        """Test validation with TLSv1.1 (should be disallowed)."""
        cipher_info = {"protocol_version": "TLSv1.1"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "TLSv1.1"
        assert "reason" in result
        assert "TLSv1.1 is not allowed" in result["reason"]

    def test_disallowed_tls_version_1_0(self):
        """Test validation with TLSv1.0 (should be disallowed)."""
        cipher_info = {"protocol_version": "TLSv1.0"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "TLSv1.0"
        assert "reason" in result
        assert "TLSv1.0 is not allowed" in result["reason"]

    def test_disallowed_ssl_version_3(self):
        """Test validation with SSLv3 (should be disallowed)."""
        cipher_info = {"protocol_version": "SSLv3"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "SSLv3"
        assert "reason" in result
        assert "SSLv3 is not allowed" in result["reason"]

    def test_disallowed_ssl_version_2(self):
        """Test validation with SSLv2 (should be disallowed)."""
        cipher_info = {"protocol_version": "SSLv2"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "SSLv2"
        assert "reason" in result
        assert "SSLv2 is not allowed" in result["reason"]

    def test_missing_protocol_version(self):
        """Test validation when protocol_version is missing."""
        cipher_info = {}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] is None
        assert "reason" in result
        assert "None is not allowed" in result["reason"]

    def test_none_protocol_version(self):
        """Test validation when protocol_version is explicitly None."""
        cipher_info = {"protocol_version": None}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] is None
        assert "reason" in result

    def test_unknown_protocol_version(self):
        """Test validation with an unknown protocol version."""
        cipher_info = {"protocol_version": "UnknownTLS"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "UnknownTLS"
        assert "reason" in result
        assert "UnknownTLS is not allowed" in result["reason"]

    def test_future_tls_version(self):
        """Test validation with a hypothetical future TLS version."""
        cipher_info = {"protocol_version": "TLSv1.4"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["protocol_version"] == "TLSv1.4"
        assert "reason" in result
        assert "TLSv1.4 is not allowed" in result["reason"]

    def test_custom_allowed_versions(self):
        """Test validation with custom allowed TLS versions."""
        # Mock the ALLOWED_TLS_VERSIONS to include TLSv1.1
        with patch(
            "certmonitor.validators.tls_version.ALLOWED_TLS_VERSIONS",
            {"TLSv1.1", "TLSv1.2", "TLSv1.3"},
        ):
            cipher_info = {"protocol_version": "TLSv1.1"}
            validator = TLSVersionValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is True
            assert result["protocol_version"] == "TLSv1.1"
            assert "reason" not in result

    def test_custom_restricted_versions(self):
        """Test validation with more restrictive allowed TLS versions."""
        # Mock the ALLOWED_TLS_VERSIONS to only include TLSv1.3
        with patch(
            "certmonitor.validators.tls_version.ALLOWED_TLS_VERSIONS", {"TLSv1.3"}
        ):
            cipher_info = {"protocol_version": "TLSv1.2"}
            validator = TLSVersionValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is False
            assert result["protocol_version"] == "TLSv1.2"
            assert "reason" in result
            assert "TLSv1.2 is not allowed" in result["reason"]

    def test_empty_allowed_versions(self):
        """Test validation when no TLS versions are allowed."""
        with patch("certmonitor.validators.tls_version.ALLOWED_TLS_VERSIONS", set()):
            cipher_info = {"protocol_version": "TLSv1.3"}
            validator = TLSVersionValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is False
            assert result["protocol_version"] == "TLSv1.3"
            assert "reason" in result

    def test_case_sensitive_version_check(self):
        """Test that TLS version checking is case-sensitive."""
        cipher_info = {
            "protocol_version": "tlsv1.3"  # lowercase
        }
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        # Should fail because ALLOWED_TLS_VERSIONS contains "TLSv1.3" not "tlsv1.3"
        assert result["is_valid"] is False
        assert result["protocol_version"] == "tlsv1.3"
        assert "reason" in result

    def test_reason_message_format(self):
        """Test that the reason message follows the expected format."""
        cipher_info = {"protocol_version": "TLSv1.0"}
        validator = TLSVersionValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert "reason" in result
        expected_parts = [
            "TLSv1.0 is not allowed",
            "Update your allowed TLS versions",
            "negotiate a supported version",
        ]
        for part in expected_parts:
            assert part in result["reason"]

    def test_validation_with_host_port_variations(self):
        """Test that host and port parameters don't affect TLS version validation."""
        cipher_info = {"protocol_version": "TLSv1.3"}
        validator = TLSVersionValidator()

        # Test with different host/port combinations
        test_cases = [
            ("example.com", 443),
            ("192.168.1.1", 8443),
            ("localhost", 3000),
            ("", 0),
        ]

        for host, port in test_cases:
            result = validator.validate(cipher_info, host, port)
            assert result["is_valid"] is True
            assert result["protocol_version"] == "TLSv1.3"

    def test_default_allowed_versions(self):
        """Test that the default allowed versions are correct."""
        from certmonitor.cipher_algorithms import ALLOWED_TLS_VERSIONS

        # Verify default allowed versions
        assert "TLSv1.2" in ALLOWED_TLS_VERSIONS
        assert "TLSv1.3" in ALLOWED_TLS_VERSIONS
        assert "TLSv1.1" not in ALLOWED_TLS_VERSIONS
        assert "TLSv1.0" not in ALLOWED_TLS_VERSIONS
        assert "SSLv3" not in ALLOWED_TLS_VERSIONS


if __name__ == "__main__":
    pytest.main([__file__])
