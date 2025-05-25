"""Final targeted tests to achieve 100% coverage for the last 2 lines."""

import pytest
from unittest.mock import patch
from certmonitor.core import CertMonitor
from certmonitor.validators.expiration import ExpirationValidator
from datetime import datetime, timedelta, timezone


def test_core_line_134_ip_address_exception():
    """Test _is_ip_address exception handling to hit core.py line 134 exactly."""
    monitor = CertMonitor("test.com")

    # Create a mock that raises ValueError when ipaddress.ip_address is called
    with patch("certmonitor.core.ipaddress.ip_address") as mock_ip_address:
        mock_ip_address.side_effect = ValueError("Invalid IP address")

        # This should trigger the except ValueError block on line 134
        result = monitor._is_ip_address("invalid.input")
        assert result is False

        # Verify ipaddress.ip_address was called
        mock_ip_address.assert_called_once_with("invalid.input")


def test_expiration_line_72_long_validity_certificate():
    """Test certificate with validity > 398 days to hit expiration.py line 72 exactly."""
    validator = ExpirationValidator()

    # Create a certificate with exactly 400 days validity to ensure we hit the > 398 condition
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=400)  # Exactly 400 days from now

    cert_data = {
        "cert_info": {
            "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        }
    }

    result = validator.validate(cert_data, "example.com", 443)

    # Verify we get the warning that hits line 72
    assert result["is_valid"] is True
    assert "warnings" in result

    # Check that we have a warning about industry standard (line 72 exactly)
    industry_warning_found = any(
        "more than industry standard" in warning for warning in result["warnings"]
    )
    assert industry_warning_found, (
        f"Expected industry standard warning. Got warnings: {result['warnings']}"
    )

    # Verify the days calculation that triggers line 72
    days_to_expiry = (not_after - now).days
    assert days_to_expiry > 398, f"Expected > 398 days, got {days_to_expiry}"


if __name__ == "__main__":
    pytest.main([__file__])
