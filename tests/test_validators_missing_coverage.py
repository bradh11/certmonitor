"""Tests to cover missing lines in validators __init__.py."""

from unittest.mock import MagicMock
import pytest

from certmonitor.validators import (
    register_validator,
    list_validators,
    get_enabled_validators,
    VALIDATORS,
)
from certmonitor.validators.base import BaseValidator


class TestValidator(BaseValidator):
    """Test validator for testing registration."""

    def __init__(self):
        super().__init__()
        self.validator_type = "cert"

    @property
    def name(self):
        return "test_validator"

    def validate(self, cert_data, host, port, *args, **kwargs):
        """Test validate method."""
        return {"is_valid": True}


def test_register_validator():
    """Test register_validator function to cover lines 34-35."""
    # Clear any existing validators
    VALIDATORS.clear()

    # Create and register a test validator
    validator = TestValidator()
    register_validator(validator)

    # Verify the validator was registered
    assert "test_validator" in VALIDATORS
    assert VALIDATORS["test_validator"] is validator


def test_list_validators():
    """Test list_validators function to cover line 45."""
    # Clear any existing validators
    VALIDATORS.clear()

    # Register multiple validators with different names
    class TestValidator1(BaseValidator):
        @property
        def name(self):
            return "validator1"

        def validate(self, cert_data, host, port):
            return {"is_valid": True}

    class TestValidator2(BaseValidator):
        @property
        def name(self):
            return "validator2"

        def validate(self, cert_data, host, port):
            return {"is_valid": True}

    validator1 = TestValidator1()
    register_validator(validator1)

    validator2 = TestValidator2()
    register_validator(validator2)

    # Test list_validators
    validator_names = list_validators()

    assert isinstance(validator_names, list)
    assert "validator1" in validator_names
    assert "validator2" in validator_names
    assert len(validator_names) == 2


def test_get_enabled_validators():
    """Test get_enabled_validators function to cover line 56."""
    # This function currently returns an empty list as a placeholder
    result = get_enabled_validators()

    assert isinstance(result, list)
    assert len(result) == 0  # Currently returns empty list


def test_validators_empty_list():
    """Test VALIDATORS dict behavior when empty."""
    # Clear validators
    VALIDATORS.clear()

    # list_validators should return empty list
    assert list_validators() == []

    # get_enabled_validators should still return empty list
    assert get_enabled_validators() == []
