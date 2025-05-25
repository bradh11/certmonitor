# tests/test_validators/test_init.py

"""Tests for validators module initialization and registration functionality."""

from certmonitor.validators import (
    VALIDATORS,
    get_enabled_validators,
    list_validators,
    register_validator,
)
from certmonitor.validators.base import BaseValidator


class MockValidator(BaseValidator):
    """Mock validator for testing registration."""

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
    """Test register_validator function."""
    # Save original validators
    original_validators = VALIDATORS.copy()

    try:
        # Clear any existing validators
        VALIDATORS.clear()

        # Create and register a test validator
        validator = MockValidator()
        register_validator(validator)

        # Verify the validator was registered
        assert "test_validator" in VALIDATORS
        assert VALIDATORS["test_validator"] is validator
    finally:
        # Restore original validators
        VALIDATORS.clear()
        VALIDATORS.update(original_validators)


def test_list_validators():
    """Test list_validators function."""
    # Save original validators
    original_validators = VALIDATORS.copy()

    try:
        # Clear any existing validators
        VALIDATORS.clear()

        # Register multiple validators with different names
        class MockValidator1(BaseValidator):
            @property
            def name(self):
                return "test1"

            def validate(self, cert_data, host, port, *args, **kwargs):
                return {"is_valid": True}

        class MockValidator2(BaseValidator):
            @property
            def name(self):
                return "test2"

            def validate(self, cert_data, host, port, *args, **kwargs):
                return {"is_valid": True}

        validator1 = MockValidator1()
        validator2 = MockValidator2()

        register_validator(validator1)
        register_validator(validator2)

        # Test list_validators function
        validator_names = list_validators()
        assert isinstance(validator_names, list)
        assert "test1" in validator_names
        assert "test2" in validator_names
        assert len(validator_names) == 2
    finally:
        # Restore original validators
        VALIDATORS.clear()
        VALIDATORS.update(original_validators)


def test_get_enabled_validators():
    """Test get_enabled_validators function."""
    # This is a placeholder function, just test it returns a list
    result = get_enabled_validators()
    assert isinstance(result, list)


def test_validators_registry_populated():
    """Test that the VALIDATORS registry is populated with default validators."""
    # Test that default validators are present
    expected_validators = [
        "expiration",
        "hostname",
        "key_info",
        "subject_alt_names",
        "root_certificate",
        "tls_version",
        "weak_cipher",
    ]

    for validator_name in expected_validators:
        assert validator_name in VALIDATORS
        assert hasattr(VALIDATORS[validator_name], "validate")
        assert hasattr(VALIDATORS[validator_name], "name")
