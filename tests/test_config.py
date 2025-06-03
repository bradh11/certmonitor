"""Tests for config module."""

import os
from unittest.mock import patch


def test_config_with_environment_variable():
    """Test config reads from environment variable."""
    # Test that environment variable is used when set
    with patch.dict(os.environ, {"ENABLED_VALIDATORS": "expiration,hostname,key_info"}):
        # Need to reload the module to pick up environment changes
        import importlib
        from certmonitor import config

        importlib.reload(config)

        assert config.ENABLED_VALIDATORS == ["expiration", "hostname", "key_info"]


def test_config_with_empty_environment_variable():
    """Test config falls back to defaults when env var is empty."""
    with patch.dict(os.environ, {"ENABLED_VALIDATORS": ""}):
        import importlib
        from certmonitor import config

        importlib.reload(config)

        assert config.ENABLED_VALIDATORS == config.DEFAULT_VALIDATORS


def test_config_with_whitespace_environment_variable():
    """Test config handles whitespace in environment variable."""
    with patch.dict(
        os.environ, {"ENABLED_VALIDATORS": " expiration , hostname , key_info "}
    ):
        import importlib
        from certmonitor import config

        importlib.reload(config)

        assert config.ENABLED_VALIDATORS == ["expiration", "hostname", "key_info"]


def test_config_with_mixed_whitespace_and_empty_values():
    """Test config handles mixed whitespace and empty values."""
    with patch.dict(
        os.environ, {"ENABLED_VALIDATORS": "expiration,,hostname, ,key_info,"}
    ):
        import importlib
        from certmonitor import config

        importlib.reload(config)

        assert config.ENABLED_VALIDATORS == ["expiration", "hostname", "key_info"]


def test_config_without_environment_variable():
    """Test config uses defaults when env var is not set."""
    # Remove the environment variable if it exists
    with patch.dict(os.environ, {}, clear=True):
        import importlib
        from certmonitor import config

        importlib.reload(config)

        assert config.ENABLED_VALIDATORS == config.DEFAULT_VALIDATORS


def test_default_validators_constant():
    """Test that DEFAULT_VALIDATORS constant is as expected."""
    from certmonitor import config

    expected_defaults = ["expiration", "hostname", "root_certificate"]
    assert config.DEFAULT_VALIDATORS == expected_defaults
