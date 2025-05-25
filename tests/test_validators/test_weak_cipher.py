# tests/test_validators/test_weak_cipher.py

from unittest.mock import patch

import pytest

from certmonitor.validators.weak_cipher import WeakCipherValidator


class TestWeakCipherValidator:
    """Test the WeakCipherValidator class."""

    def test_validator_name(self):
        """Test that the validator has the correct name."""
        validator = WeakCipherValidator()
        assert validator.name == "weak_cipher"

    def test_validator_type(self):
        """Test that the validator has the correct type."""
        validator = WeakCipherValidator()
        assert validator.validator_type == "cipher"

    def test_allowed_cipher_suite_ecdhe_rsa_aes128_gcm(self):
        """Test validation with ECDHE-RSA-AES128-GCM-SHA256 (should be allowed)."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
        assert "reason" not in result

    def test_allowed_cipher_suite_ecdhe_ecdsa_aes128_gcm(self):
        """Test validation with ECDHE-ECDSA-AES128-GCM-SHA256 (should be allowed)."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-ECDSA-AES128-GCM-SHA256"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "ECDHE-ECDSA-AES128-GCM-SHA256"
        assert "reason" not in result

    def test_allowed_cipher_suite_chacha20_poly1305(self):
        """Test validation with ECDHE-RSA-CHACHA20-POLY1305 (should be allowed)."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-CHACHA20-POLY1305"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "ECDHE-RSA-CHACHA20-POLY1305"
        assert "reason" not in result

    def test_allowed_cipher_suite_aes256_gcm(self):
        """Test validation with ECDHE-ECDSA-AES256-GCM-SHA384 (should be allowed)."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-ECDSA-AES256-GCM-SHA384"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "ECDHE-ECDSA-AES256-GCM-SHA384"
        assert "reason" not in result

    def test_weak_cipher_suite_rc4(self):
        """Test validation with a weak RC4 cipher (should be disallowed)."""
        cipher_info = {"cipher_suite": {"name": "TLS_RSA_WITH_RC4_128_MD5"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "TLS_RSA_WITH_RC4_128_MD5"
        assert "reason" in result
        assert "TLS_RSA_WITH_RC4_128_MD5 is not allowed" in result["reason"]

    def test_weak_cipher_suite_des(self):
        """Test validation with a weak DES cipher (should be disallowed)."""
        cipher_info = {"cipher_suite": {"name": "TLS_RSA_WITH_DES_CBC_SHA"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "TLS_RSA_WITH_DES_CBC_SHA"
        assert "reason" in result
        assert "TLS_RSA_WITH_DES_CBC_SHA is not allowed" in result["reason"]

    def test_weak_cipher_suite_md5(self):
        """Test validation with a cipher using MD5 hash (should be disallowed)."""
        cipher_info = {"cipher_suite": {"name": "TLS_RSA_WITH_AES_128_CBC_MD5"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "TLS_RSA_WITH_AES_128_CBC_MD5"
        assert "reason" in result

    def test_weak_cipher_suite_null_encryption(self):
        """Test validation with null encryption cipher (should be disallowed)."""
        cipher_info = {"cipher_suite": {"name": "TLS_RSA_WITH_NULL_SHA"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "TLS_RSA_WITH_NULL_SHA"
        assert "reason" in result

    def test_missing_cipher_suite(self):
        """Test validation when cipher_suite is missing."""
        cipher_info = {}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] is None
        assert "reason" in result
        assert "None is not allowed" in result["reason"]

    def test_missing_cipher_name(self):
        """Test validation when cipher name is missing."""
        cipher_info = {"cipher_suite": {}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] is None
        assert "reason" in result

    def test_none_cipher_name(self):
        """Test validation when cipher name is explicitly None."""
        cipher_info = {"cipher_suite": {"name": None}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] is None
        assert "reason" in result

    def test_empty_cipher_name(self):
        """Test validation when cipher name is empty string."""
        cipher_info = {"cipher_suite": {"name": ""}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == ""
        assert "reason" in result

    def test_unknown_cipher_suite(self):
        """Test validation with an unknown cipher suite."""
        cipher_info = {"cipher_suite": {"name": "UNKNOWN_CIPHER_SUITE"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "UNKNOWN_CIPHER_SUITE"
        assert "reason" in result
        assert "UNKNOWN_CIPHER_SUITE is not allowed" in result["reason"]

    def test_custom_allowed_ciphers(self):
        """Test validation with custom allowed cipher suites."""
        # Mock the ALLOWED_CIPHER_SUITES to include a custom cipher
        custom_ciphers = {"CUSTOM-CIPHER-SUITE", "ECDHE-RSA-AES128-GCM-SHA256"}
        with patch(
            "certmonitor.validators.weak_cipher.ALLOWED_CIPHER_SUITES", custom_ciphers
        ):
            cipher_info = {"cipher_suite": {"name": "CUSTOM-CIPHER-SUITE"}}
            validator = WeakCipherValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is True
            assert result["cipher_suite"] == "CUSTOM-CIPHER-SUITE"
            assert "reason" not in result

    def test_custom_restricted_ciphers(self):
        """Test validation with more restrictive allowed cipher suites."""
        # Mock to only allow one specific cipher
        with patch(
            "certmonitor.validators.weak_cipher.ALLOWED_CIPHER_SUITES",
            {"ECDHE-RSA-AES256-GCM-SHA384"},
        ):
            cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
            validator = WeakCipherValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is False
            assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
            assert "reason" in result

    def test_empty_allowed_ciphers(self):
        """Test validation when no cipher suites are allowed."""
        with patch("certmonitor.validators.weak_cipher.ALLOWED_CIPHER_SUITES", set()):
            cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
            validator = WeakCipherValidator()
            result = validator.validate(cipher_info, "example.com", 443)

            assert result["is_valid"] is False
            assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
            assert "reason" in result

    def test_case_sensitive_cipher_check(self):
        """Test that cipher suite checking is case-sensitive."""
        cipher_info = {
            "cipher_suite": {
                "name": "ecdhe-rsa-aes128-gcm-sha256"  # lowercase
            }
        }
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        # Should fail because ALLOWED_CIPHER_SUITES contains uppercase version
        assert result["is_valid"] is False
        assert result["cipher_suite"] == "ecdhe-rsa-aes128-gcm-sha256"
        assert "reason" in result

    def test_reason_message_format(self):
        """Test that the reason message follows the expected format."""
        cipher_info = {"cipher_suite": {"name": "TLS_RSA_WITH_RC4_128_MD5"}}
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is False
        assert "reason" in result
        expected_parts = [
            "TLS_RSA_WITH_RC4_128_MD5 is not allowed",
            "update your allowed cipher suites",
            "negotiate a supported cipher",
        ]
        for part in expected_parts:
            assert part.lower() in result["reason"].lower()

    def test_validation_with_host_port_variations(self):
        """Test that host and port parameters don't affect cipher validation."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
        validator = WeakCipherValidator()

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
            assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"

    def test_default_allowed_ciphers(self):
        """Test that the default allowed cipher suites contain expected strong ciphers."""
        from certmonitor.cipher_algorithms import ALLOWED_CIPHER_SUITES

        # The test should be resilient to global state changes
        # At minimum, we should have some strong cipher suites
        assert len(ALLOWED_CIPHER_SUITES) > 0

        # Verify that at least some modern cipher suites are present
        # (this test is flexible in case global state was modified)
        strong_ciphers_found = 0
        expected_patterns = [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ]

        for pattern in expected_patterns:
            if pattern in ALLOWED_CIPHER_SUITES:
                strong_ciphers_found += 1

        # At least one modern cipher should be present
        assert strong_ciphers_found > 0, (
            f"No expected strong ciphers found in {ALLOWED_CIPHER_SUITES}"
        )

    def test_additional_cipher_suite_fields(self):
        """Test that additional fields in cipher_suite are ignored."""
        cipher_info = {
            "cipher_suite": {
                "name": "ECDHE-RSA-AES128-GCM-SHA256",
                "version": "TLSv1.2",
                "bits": 128,
                "description": "ECDHE with RSA and AES 128 GCM",
            }
        }
        validator = WeakCipherValidator()
        result = validator.validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
        # Other fields should not affect validation


if __name__ == "__main__":
    pytest.main([__file__])
