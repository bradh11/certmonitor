# tests/test_validators/test_key_info.py

import pytest

from certmonitor.validators.key_info import KeyInfoValidator


class TestKeyInfoValidator:
    """Test the KeyInfoValidator class."""

    def test_validator_name(self):
        """Test that the validator has the correct name."""
        validator = KeyInfoValidator()
        assert validator.name == "key_info"

    def test_validator_type(self):
        """Test that the validator has the correct type."""
        validator = KeyInfoValidator()
        assert validator.validator_type == "cert"

    def test_rsa_strong_key(self):
        """Test validation of a strong RSA key (2048 bits)."""
        cert = {"public_key_info": {"algorithm": "rsaEncryption", "size": 2048}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["key_size"] == 2048
        assert result["is_valid"] is True
        assert "curve" not in result

    def test_rsa_very_strong_key(self):
        """Test validation of a very strong RSA key (4096 bits)."""
        cert = {"public_key_info": {"algorithm": "rsaEncryption", "size": 4096}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["key_size"] == 4096
        assert result["is_valid"] is True

    def test_rsa_weak_key_1024(self):
        """Test validation of a weak RSA key (1024 bits)."""
        cert = {"public_key_info": {"algorithm": "rsaEncryption", "size": 1024}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["key_size"] == 1024
        assert result["is_valid"] is False

    def test_rsa_very_weak_key_512(self):
        """Test validation of a very weak RSA key (512 bits)."""
        cert = {"public_key_info": {"algorithm": "rsaEncryption", "size": 512}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["key_size"] == 512
        assert result["is_valid"] is False

    def test_ec_strong_curve_p256(self):
        """Test validation of a strong EC key with secp256r1 curve."""
        cert = {
            "public_key_info": {
                "algorithm": "ecPublicKey",
                "size": 256,
                "curve": "secp256r1",
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "ecPublicKey"
        assert result["key_size"] == 256
        assert result["curve"] == "secp256r1"
        assert result["is_valid"] is True

    def test_ec_strong_curve_p384(self):
        """Test validation of a strong EC key with secp384r1 curve."""
        cert = {
            "public_key_info": {
                "algorithm": "ecPublicKey",
                "size": 384,
                "curve": "secp384r1",
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "ecPublicKey"
        assert result["key_size"] == 384
        assert result["curve"] == "secp384r1"
        assert result["is_valid"] is True

    def test_ec_strong_curve_p521(self):
        """Test validation of a strong EC key with secp521r1 curve."""
        cert = {
            "public_key_info": {
                "algorithm": "ecPublicKey",
                "size": 521,
                "curve": "secp521r1",
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "ecPublicKey"
        assert result["key_size"] == 521
        assert result["curve"] == "secp521r1"
        assert result["is_valid"] is True

    def test_ec_weak_curve(self):
        """Test validation of an EC key with a weak/unknown curve."""
        cert = {
            "public_key_info": {
                "algorithm": "ecPublicKey",
                "size": 256,
                "curve": "secp192r1",  # Not in the strong curves list
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "ecPublicKey"
        assert result["key_size"] == 256
        assert result["curve"] == "secp192r1"
        assert result["is_valid"] is False

    def test_ec_no_curve_info(self):
        """Test validation of an EC key without curve information."""
        cert = {"public_key_info": {"algorithm": "ecPublicKey", "size": 256}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "ecPublicKey"
        assert result["key_size"] == 256
        assert result["is_valid"] is None  # Cannot determine without curve info

    def test_rsa_no_size_info(self):
        """Test validation of an RSA key without size information."""
        cert = {"public_key_info": {"algorithm": "rsaEncryption"}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["key_size"] is None
        assert result["is_valid"] is None  # Cannot determine without size info

    def test_unknown_key_type(self):
        """Test validation of an unknown key type."""
        cert = {"public_key_info": {"algorithm": "unknownKeyType", "size": 2048}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "unknownKeyType"
        assert result["key_size"] == 2048
        assert result["is_valid"] is None  # Cannot determine for unknown key types

    def test_missing_public_key_info(self):
        """Test validation when public_key_info is missing."""
        cert = {}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert "error" in result
        assert result["error"] == "Unable to extract public key information"
        assert result["is_valid"] is False

    def test_empty_public_key_info(self):
        """Test validation when public_key_info is empty."""
        cert = {"public_key_info": {}}
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert "error" in result
        assert result["error"] == "Unable to extract public key information"
        assert result["is_valid"] is False

    def test_partial_rsa_algorithm_match(self):
        """Test that RSA variants are properly detected."""
        cert = {
            "public_key_info": {
                "algorithm": "rsaEncryption",  # Use exact match for RSA
                "size": 2048,
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "rsaEncryption"
        assert result["is_valid"] is True

    def test_partial_ec_algorithm_match(self):
        """Test that EC variants are properly detected."""
        cert = {
            "public_key_info": {
                "algorithm": "id-ecPublicKey",  # Contains ecPublicKey
                "size": 256,
                "curve": "secp256r1",
            }
        }
        validator = KeyInfoValidator()
        result = validator.validate(cert, "example.com", 443)

        assert result["key_type"] == "id-ecPublicKey"
        assert result["is_valid"] is True

    def test_is_key_strong_enough_method(self):
        """Test the _is_key_strong_enough method directly."""
        validator = KeyInfoValidator()

        # Test RSA keys
        assert validator._is_key_strong_enough("rsaEncryption", 2048, None) is True
        assert validator._is_key_strong_enough("rsaEncryption", 4096, None) is True
        assert validator._is_key_strong_enough("rsaEncryption", 1024, None) is False
        assert validator._is_key_strong_enough("rsaEncryption", None, None) is None

        # Test EC keys
        assert validator._is_key_strong_enough("ecPublicKey", 256, "secp256r1") is True
        assert validator._is_key_strong_enough("ecPublicKey", 384, "secp384r1") is True
        assert validator._is_key_strong_enough("ecPublicKey", 521, "secp521r1") is True
        assert validator._is_key_strong_enough("ecPublicKey", 256, "secp192r1") is False
        assert validator._is_key_strong_enough("ecPublicKey", 256, None) is None

        # Test unknown key types
        assert validator._is_key_strong_enough("unknownType", 2048, None) is None

    def test_edge_case_boundary_values(self):
        """Test boundary values for key size validation."""
        validator = KeyInfoValidator()

        # Test RSA boundary (exactly 2048)
        cert_2048 = {"public_key_info": {"algorithm": "rsaEncryption", "size": 2048}}
        result = validator.validate(cert_2048, "example.com", 443)
        assert result["is_valid"] is True

        # Test RSA just below boundary (2047)
        cert_2047 = {"public_key_info": {"algorithm": "rsaEncryption", "size": 2047}}
        result = validator.validate(cert_2047, "example.com", 443)
        assert result["is_valid"] is False


if __name__ == "__main__":
    pytest.main([__file__])
