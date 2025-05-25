# tests/test_validators/test_base.py

import pytest
from abc import ABCMeta

from certmonitor.validators.base import (
    BaseValidator,
    BaseCertValidator,
    BaseCipherValidator,
)


class TestBaseValidator:
    """Test the abstract BaseValidator class."""

    def test_base_validator_is_abstract(self):
        """Test that BaseValidator cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseValidator()

    def test_base_validator_has_abstract_methods(self):
        """Test that BaseValidator has the required abstract methods."""
        assert hasattr(BaseValidator, "name")
        assert hasattr(BaseValidator, "validate")
        assert isinstance(BaseValidator, ABCMeta)

    def test_concrete_validator_can_inherit(self):
        """Test that a concrete validator can inherit from BaseValidator."""

        class ConcreteValidator(BaseValidator):
            @property
            def name(self):
                return "test_validator"

            def validate(self, cert, host, port):
                return {"is_valid": True}

        validator = ConcreteValidator()
        assert validator.name == "test_validator"
        result = validator.validate({}, "example.com", 443)
        assert result["is_valid"] is True

    def test_incomplete_concrete_validator_fails(self):
        """Test that incomplete concrete validators cannot be instantiated."""

        class IncompleteValidator(BaseValidator):
            @property
            def name(self):
                return "incomplete"

            # Missing validate method

        with pytest.raises(TypeError):
            IncompleteValidator()


class TestBaseCertValidator:
    """Test the BaseCertValidator class."""

    def test_base_cert_validator_inheritance(self):
        """Test that BaseCertValidator inherits from BaseValidator."""
        assert issubclass(BaseCertValidator, BaseValidator)

    def test_base_cert_validator_type(self):
        """Test that BaseCertValidator has correct validator_type."""
        assert BaseCertValidator.validator_type == "cert"

    def test_base_cert_validator_validate_method(self):
        """Test the validate method signature with concrete implementation."""

        # Create a concrete implementation since BaseCertValidator is also abstract
        class ConcreteCertValidator(BaseCertValidator):
            @property
            def name(self):
                return "test_cert_validator"

        validator = ConcreteCertValidator()
        # Should not raise an error, but returns None by default
        result = validator.validate({}, "example.com", 443)
        assert result is None

    def test_concrete_cert_validator(self):
        """Test that a concrete cert validator works properly."""

        class ConcreteCertValidator(BaseCertValidator):
            @property
            def name(self):
                return "test_cert_validator"

            def validate(self, cert_info, host, port):
                return {"is_valid": True, "validator_type": self.validator_type}

        validator = ConcreteCertValidator()
        assert validator.name == "test_cert_validator"
        assert validator.validator_type == "cert"
        result = validator.validate({}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["validator_type"] == "cert"


class TestBaseCipherValidator:
    """Test the BaseCipherValidator class."""

    def test_base_cipher_validator_inheritance(self):
        """Test that BaseCipherValidator inherits from BaseValidator."""
        assert issubclass(BaseCipherValidator, BaseValidator)

    def test_base_cipher_validator_type(self):
        """Test that BaseCipherValidator has correct validator_type."""
        assert BaseCipherValidator.validator_type == "cipher"

    def test_base_cipher_validator_validate_method(self):
        """Test the validate method signature with concrete implementation."""

        # Create a concrete implementation since BaseCipherValidator is also abstract
        class ConcreteCipherValidator(BaseCipherValidator):
            @property
            def name(self):
                return "test_cipher_validator"

        validator = ConcreteCipherValidator()
        # Should not raise an error, but returns None by default
        result = validator.validate({}, "example.com", 443)
        assert result is None

    def test_concrete_cipher_validator(self):
        """Test that a concrete cipher validator works properly."""

        class ConcreteCipherValidator(BaseCipherValidator):
            @property
            def name(self):
                return "test_cipher_validator"

            def validate(self, cipher_info, host, port):
                return {"is_valid": True, "validator_type": self.validator_type}

        validator = ConcreteCipherValidator()
        assert validator.name == "test_cipher_validator"
        assert validator.validator_type == "cipher"
        result = validator.validate({}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["validator_type"] == "cipher"


class TestValidatorInterfaces:
    """Test the validator interfaces and polymorphism."""

    def test_validator_polymorphism(self):
        """Test that different validator types can be used polymorphically."""

        class TestCertValidator(BaseCertValidator):
            @property
            def name(self):
                return "test_cert"

            def validate(self, cert_info, host, port):
                return {"type": "cert", "is_valid": True}

        class TestCipherValidator(BaseCipherValidator):
            @property
            def name(self):
                return "test_cipher"

            def validate(self, cipher_info, host, port):
                return {"type": "cipher", "is_valid": True}

        validators = [TestCertValidator(), TestCipherValidator()]

        for validator in validators:
            assert hasattr(validator, "name")
            assert hasattr(validator, "validate")
            assert hasattr(validator, "validator_type")
            result = validator.validate({}, "example.com", 443)
            assert result["is_valid"] is True

    def test_validator_name_property(self):
        """Test that name property works correctly."""

        class NamedValidator(BaseCertValidator):
            @property
            def name(self):
                return "custom_name"

            def validate(self, cert_info, host, port):
                return {"is_valid": True}

        validator = NamedValidator()
        assert validator.name == "custom_name"


if __name__ == "__main__":
    pytest.main([__file__])
