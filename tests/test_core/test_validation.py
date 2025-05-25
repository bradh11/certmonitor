"""Tests for CertMonitor validation operations and validator execution."""

from unittest.mock import MagicMock, patch

import pytest

from certmonitor.core import CertMonitor


class TestBasicValidation:
    """Test basic validation functionality."""

    def test_validate(self, cert_monitor, sample_cert):
        """Test basic validate function with sample certificate."""
        cert_monitor.cert_info = sample_cert  # Not wrapped
        cert_monitor.cert_data = {"cert_info": sample_cert}  # Needed for validate()
        mock_validator = MagicMock(name="mock_validator")
        mock_validator.name = "mock_validator"
        mock_validator.validator_type = "cert"
        mock_validator.validate.return_value = {"is_valid": True}
        with patch.object(
            cert_monitor, "validators", {"mock_validator": mock_validator}
        ):
            cert_monitor.enabled_validators = ["mock_validator"]
            result = cert_monitor.validate()
        assert "mock_validator" in result

    def test_validate_with_args(self, cert_monitor, sample_cert):
        """Test validate function with additional arguments."""
        cert_monitor.cert_info = sample_cert  # Not wrapped
        cert_monitor.cert_data = {"cert_info": sample_cert}  # Needed for validate()
        mock_validator = MagicMock(name="subject_alt_names")
        mock_validator.name = "subject_alt_names"
        mock_validator.validator_type = "cert"
        mock_validator.validate.return_value = {"is_valid": True}
        with patch.object(
            cert_monitor, "validators", {"subject_alt_names": mock_validator}
        ):
            cert_monitor.enabled_validators = ["subject_alt_names"]
            result = cert_monitor.validate(
                validator_args={"subject_alt_names": ["example.com"]}
            )
        assert "subject_alt_names" in result
        mock_validator.validate.assert_called_once_with(
            {"cert_info": sample_cert},
            cert_monitor.host,
            cert_monitor.port,
            ["example.com"],
        )


class TestValidatorExecution:
    """Test different validator types and their execution scenarios."""

    def test_validate_unknown_validators(self):
        """Test validate() handles unknown validators."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["unknown_validator", "another_unknown"]

        result = monitor.validate()

        assert "unknown_validator" in result
        assert "another_unknown" in result
        assert result["unknown_validator"]["is_valid"] is False
        assert "not implemented" in result["unknown_validator"]["reason"]


class TestCertValidators:
    """Test certificate-specific validator scenarios."""

    def test_validate_cert_validators_no_cert_data(self):
        """Test validate() handles missing cert data for cert validators."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["hostname"]

        # Mock a cert validator
        mock_validator = MagicMock()
        mock_validator.name = "hostname"
        mock_validator.validator_type = "cert"

        with patch.object(monitor, "validators", {"hostname": mock_validator}):
            # No cert_data attribute
            result = monitor.validate()

            assert "hostname" in result
            assert result["hostname"]["is_valid"] is False
            assert "Certificate data is missing" in result["hostname"]["reason"]

    def test_validate_cert_validators_cert_data_error(self):
        """Test validate() handles cert data with errors."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["hostname"]
        monitor.cert_data = {
            "error": "CertificateError",
            "message": "Failed to fetch certificate",
        }

        # Mock a cert validator
        mock_validator = MagicMock()
        mock_validator.name = "hostname"
        mock_validator.validator_type = "cert"

        with patch.object(monitor, "validators", {"hostname": mock_validator}):
            result = monitor.validate()

            assert "hostname" in result
            assert result["hostname"]["is_valid"] is False
            assert "CertificateError" in result["hostname"]["reason"]

    def test_validate_cert_validators_success(self):
        """Test validate() successful cert validator execution."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["hostname"]
        monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

        # Mock a cert validator
        mock_validator = MagicMock()
        mock_validator.name = "hostname"
        mock_validator.validator_type = "cert"
        mock_validator.validate.return_value = {
            "is_valid": True,
            "reason": "Hostname matches",
        }

        with patch.object(monitor, "validators", {"hostname": mock_validator}):
            result = monitor.validate()

            assert "hostname" in result
            assert result["hostname"]["is_valid"] is True
            mock_validator.validate.assert_called_once_with(
                monitor.cert_data, monitor.host, monitor.port
            )

    def test_validate_cert_validators_with_subject_alt_names_args(self):
        """Test validate() with subject_alt_names validator arguments."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["subject_alt_names"]
        monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

        # Mock subject_alt_names validator
        mock_validator = MagicMock()
        mock_validator.name = "subject_alt_names"
        mock_validator.validator_type = "cert"
        mock_validator.validate.return_value = {"is_valid": True}

        with patch.object(monitor, "validators", {"subject_alt_names": mock_validator}):
            validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
            result = monitor.validate(validator_args=validator_args)

            assert "subject_alt_names" in result
            mock_validator.validate.assert_called_once_with(
                monitor.cert_data,
                monitor.host,
                monitor.port,
                ["example.com", "www.example.com"],
            )

    def test_validate_cert_validators_with_other_args(self):
        """Test validate() with other validator arguments (non-subject_alt_names)."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["custom_validator"]
        monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

        # Mock custom validator
        mock_validator = MagicMock()
        mock_validator.name = "custom_validator"
        mock_validator.validator_type = "cert"
        mock_validator.validate.return_value = {"is_valid": True}

        with patch.object(monitor, "validators", {"custom_validator": mock_validator}):
            validator_args = {"custom_validator": ["arg1", "arg2"]}
            result = monitor.validate(validator_args=validator_args)

            assert "custom_validator" in result
            mock_validator.validate.assert_called_once_with(
                monitor.cert_data, monitor.host, monitor.port, "arg1", "arg2"
            )


class TestCipherValidators:
    """Test cipher-specific validator scenarios."""

    def test_validate_cipher_validators_success(self):
        """Test validate() successful cipher validator execution."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["weak_cipher"]

        # Mock cipher validator
        mock_validator = MagicMock()
        mock_validator.name = "weak_cipher"
        mock_validator.validator_type = "cipher"
        mock_validator.validate.return_value = {
            "is_valid": True,
            "reason": "Strong cipher",
        }

        mock_cipher_info = {
            "cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"},
            "protocol_version": "TLSv1.2",
        }

        with patch.object(monitor, "validators", {"weak_cipher": mock_validator}):
            with patch.object(
                monitor, "get_cipher_info", return_value=mock_cipher_info
            ):
                result = monitor.validate()

                assert "weak_cipher" in result
                assert result["weak_cipher"]["is_valid"] is True
                mock_validator.validate.assert_called_once_with(
                    mock_cipher_info, monitor.host, monitor.port
                )

    def test_validate_cipher_validators_cipher_error(self):
        """Test validate() handles cipher info errors for cipher validators."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["weak_cipher"]

        # Mock cipher validator
        mock_validator = MagicMock()
        mock_validator.name = "weak_cipher"
        mock_validator.validator_type = "cipher"

        cipher_error = {
            "error": "ConnectionError",
            "message": "Failed to get cipher info",
        }

        with patch.object(monitor, "validators", {"weak_cipher": mock_validator}):
            with patch.object(monitor, "get_cipher_info", return_value=cipher_error):
                result = monitor.validate()

                # Cipher validators should be skipped when cipher info has errors
                assert "weak_cipher" not in result or len(result) == 0

    def test_validate_cipher_validators_with_args(self):
        """Test validate() cipher validators with additional arguments."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["custom_cipher_validator"]

        # Mock cipher validator
        mock_validator = MagicMock()
        mock_validator.name = "custom_cipher_validator"
        mock_validator.validator_type = "cipher"
        mock_validator.validate.return_value = {"is_valid": True}

        mock_cipher_info = {"cipher_suite": {"name": "test"}}

        with patch.object(
            monitor, "validators", {"custom_cipher_validator": mock_validator}
        ):
            with patch.object(
                monitor, "get_cipher_info", return_value=mock_cipher_info
            ):
                validator_args = {"custom_cipher_validator": ["arg1", "arg2"]}
                result = monitor.validate(validator_args=validator_args)

                assert "custom_cipher_validator" in result
                mock_validator.validate.assert_called_once_with(
                    mock_cipher_info, monitor.host, monitor.port, "arg1", "arg2"
                )


class TestMixedValidators:
    """Test scenarios with multiple validator types."""

    def test_validate_mixed_validators(self):
        """Test validate() with both cert and cipher validators."""
        monitor = CertMonitor("www.example.com")
        monitor.enabled_validators = ["hostname", "weak_cipher"]
        monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

        # Mock cert validator
        mock_cert_validator = MagicMock()
        mock_cert_validator.name = "hostname"
        mock_cert_validator.validator_type = "cert"
        mock_cert_validator.validate.return_value = {"is_valid": True}

        # Mock cipher validator
        mock_cipher_validator = MagicMock()
        mock_cipher_validator.name = "weak_cipher"
        mock_cipher_validator.validator_type = "cipher"
        mock_cipher_validator.validate.return_value = {"is_valid": True}

        mock_cipher_info = {"cipher_suite": {"name": "test"}}

        validators = {
            "hostname": mock_cert_validator,
            "weak_cipher": mock_cipher_validator,
        }

        with patch.object(monitor, "validators", validators):
            with patch.object(
                monitor, "get_cipher_info", return_value=mock_cipher_info
            ):
                result = monitor.validate()

                assert "hostname" in result
                assert "weak_cipher" in result
                assert result["hostname"]["is_valid"] is True
                assert result["weak_cipher"]["is_valid"] is True
