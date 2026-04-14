# tests/test_validators/test_base.py

from abc import ABCMeta

import pytest

from certmonitor.validators.base import (
    BaseCertValidator,
    BaseCipherValidator,
    BaseValidator,
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


class TestUserArgEnforcement:
    """Test the __init_subclass__ enforcement of user-arg declarations."""

    def test_validator_with_no_user_args_is_allowed(self):
        """A validator with only framework params and no user args passes."""

        class NoUserArgsValidator(BaseCertValidator):
            @property
            def name(self):
                return "no_user_args"

            def validate(self, cert_info, host, port):
                return {"is_valid": True}

        v = NoUserArgsValidator()
        assert v._user_param_names == frozenset()

    def test_validator_with_well_formed_user_arg_is_allowed(self):
        """A keyword-only, annotated, defaulted user arg is accepted."""
        from typing import Optional, List

        class WellFormedValidator(BaseCertValidator):
            @property
            def name(self):
                return "well_formed"

            def validate(
                self,
                cert_info,
                host,
                port,
                *,
                names: Optional[List[str]] = None,
            ):
                return {"is_valid": True, "names": names}

        v = WellFormedValidator()
        assert v._user_param_names == frozenset({"names"})
        assert "names" in v._user_params

    def test_validator_with_positional_user_arg_is_rejected(self):
        """A positional-or-keyword user arg fails enforcement at class creation."""
        with pytest.raises(TypeError, match="must be keyword-only"):

            class BadPositionalValidator(BaseCertValidator):
                @property
                def name(self):
                    return "bad_positional"

                def validate(self, cert_info, host, port, names=None):
                    return {"is_valid": True}

    def test_validator_with_unannotated_user_arg_is_rejected(self):
        """A keyword-only user arg without a type annotation fails."""
        with pytest.raises(TypeError, match="missing type annotation"):

            class BadUnannotatedValidator(BaseCertValidator):
                @property
                def name(self):
                    return "bad_unannotated"

                def validate(self, cert_info, host, port, *, names=None):
                    return {"is_valid": True}

    def test_validator_with_no_default_user_arg_is_rejected(self):
        """A keyword-only annotated user arg without a default fails."""
        from typing import List

        with pytest.raises(TypeError, match="missing default value"):

            class BadNoDefaultValidator(BaseCertValidator):
                @property
                def name(self):
                    return "bad_no_default"

                def validate(self, cert_info, host, port, *, names: List[str]):
                    return {"is_valid": True}

    def test_validator_with_var_positional_is_rejected(self):
        """``*args`` for user args is rejected."""
        with pytest.raises(TypeError, match=r"\*args is not allowed"):

            class BadVarPositionalValidator(BaseCertValidator):
                @property
                def name(self):
                    return "bad_varargs"

                def validate(self, cert_info, host, port, *names):
                    return {"is_valid": True}

    def test_validator_with_var_keyword_is_rejected(self):
        """``**kwargs`` for user args is rejected — every arg must be explicit."""
        with pytest.raises(TypeError, match=r"\*\*kwargs is not allowed"):

            class BadVarKeywordValidator(BaseCertValidator):
                @property
                def name(self):
                    return "bad_kwargs"

                def validate(self, cert_info, host, port, **opts):
                    return {"is_valid": True}

    def test_cipher_validator_enforcement(self):
        """Cipher validators get the same enforcement as cert validators."""
        with pytest.raises(TypeError, match="must be keyword-only"):

            class BadCipherValidator(BaseCipherValidator):
                @property
                def name(self):
                    return "bad_cipher"

                def validate(self, cipher_info, host, port, threshold=0):
                    return {"is_valid": True}


if __name__ == "__main__":
    pytest.main([__file__])
