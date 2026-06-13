# tests/test_validators/test_weak_cipher.py

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

    @pytest.mark.parametrize(
        "cipher_name",
        [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
    )
    def test_allowed_tls13_cipher_suites(self, cipher_name):
        """TLS 1.3 cipher suites must be allowed (issue #50).

        tls_version permits TLS 1.3, so the suites a TLS 1.3 handshake
        actually negotiates (reported by Python's ssl module under their
        IANA names) must validate as strong. Previously the allow-list held
        only TLS 1.2 names, so every modern site failed.
        """
        cipher_info = {"cipher_suite": {"name": cipher_name}}
        result = WeakCipherValidator().validate(cipher_info, "example.com", 443)

        assert result["is_valid"] is True, result
        assert result["cipher_suite"] == cipher_name
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
        """A custom allowed_cipher_suites arg lets through a custom cipher."""
        cipher_info = {"cipher_suite": {"name": "CUSTOM-CIPHER-SUITE"}}
        validator = WeakCipherValidator()
        result = validator.validate(
            cipher_info,
            "example.com",
            443,
            allowed_cipher_suites=[
                "CUSTOM-CIPHER-SUITE",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ],
        )

        assert result["is_valid"] is True
        assert result["cipher_suite"] == "CUSTOM-CIPHER-SUITE"
        assert "reason" not in result

    def test_custom_restricted_ciphers(self):
        """A restrictive allowed_cipher_suites arg rejects an otherwise-strong cipher."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
        validator = WeakCipherValidator()
        result = validator.validate(
            cipher_info,
            "example.com",
            443,
            allowed_cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
        )

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
        assert "reason" in result

    def test_empty_allowed_ciphers(self):
        """An empty allowed_cipher_suites arg rejects everything."""
        cipher_info = {"cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"}}
        validator = WeakCipherValidator()
        result = validator.validate(
            cipher_info, "example.com", 443, allowed_cipher_suites=[]
        )

        assert result["is_valid"] is False
        assert result["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
        assert "reason" in result

    def test_dhe_rsa_allowed_by_default(self):
        """DHE-RSA AEAD suites are part of Mozilla Intermediate and pass by default."""
        validator = WeakCipherValidator()
        for name in (
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-CHACHA20-POLY1305",
        ):
            result = validator.validate(
                {"cipher_suite": {"name": name}}, "example.com", 443
            )
            assert result["is_valid"] is True, name

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
        """The validator's default allowed cipher suites contain strong ciphers."""
        from certmonitor.validators.weak_cipher import _DEFAULT_ALLOWED_CIPHER_SUITES

        assert len(_DEFAULT_ALLOWED_CIPHER_SUITES) > 0
        for pattern in (
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ):
            assert pattern in _DEFAULT_ALLOWED_CIPHER_SUITES

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
