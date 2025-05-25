"""Tests to cover the final missing lines for 100% coverage."""

import pytest
from certmonitor.core import CertMonitor
from certmonitor.protocol_handlers.base import BaseProtocolHandler
from certmonitor.validators.expiration import ExpirationValidator
from datetime import datetime, timedelta


def test_ip_address_exception_handling_line_134():
    """Test _is_ip_address exception handling to cover core.py line 134."""
    monitor = CertMonitor("example.com")

    # These should trigger the ValueError exception and cover line 134
    test_cases = [
        "definitely.not.an.ip",
        "999.999.999.999",  # Invalid IP range
        "256.256.256.256",  # Out of range IP
        "192.168.1",  # Incomplete IP
        "invalid-hostname",
        "",  # Empty string
        ":::invalid::ipv6:::",  # Invalid IPv6
    ]

    for invalid_input in test_cases:
        # This should hit the except ValueError block on line 134
        result = monitor._is_ip_address(invalid_input)
        assert result is False


def test_base_protocol_handler_abstract_methods_lines_16_20_24():
    """Test base protocol handler abstract methods to cover lines 16, 20, 24."""

    # The abstract methods in BaseProtocolHandler contain "pass" statements on lines 16, 20, 24
    # We need to create a scenario where these lines are executed

    # Create a handler that deliberately calls the parent abstract methods to hit the pass statements
    class TestHandler(BaseProtocolHandler):
        def __init__(self, host, port):
            super().__init__(host, port, error_handler=None)

        def connect(self):
            # This will execute the pass statement on line 16
            super().connect()
            return None

        def fetch_raw_cert(self):
            # This will execute the pass statement on line 20
            super().fetch_raw_cert()
            return {}

        def close(self):
            # This will execute the pass statement on line 24
            super().close()

    handler = TestHandler("example.com", 443)

    # Call the methods to execute the pass statements in the abstract methods
    handler.connect()  # Covers line 16
    handler.fetch_raw_cert()  # Covers line 20
    handler.close()  # Covers line 24


def test_expiration_validator_long_validity_warning_line_72():
    """Test expiration validator warning for certificates valid > 398 days to cover line 72."""
    validator = ExpirationValidator()

    # Create a certificate that's valid for more than 398 days (e.g., 2 years)
    # Use the correct date format expected by the validator: "%b %d %H:%M:%S %Y GMT"
    now = datetime.utcnow()
    not_before = now - timedelta(days=1)  # Valid from yesterday
    not_after = now + timedelta(days=730)  # Valid for 2 years (730 days)

    cert_data = {
        "cert_info": {
            "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        }
    }

    result = validator.validate(cert_data, "example.com", 443)

    # Should be valid but have a warning about long validity period
    assert result["is_valid"] is True
    assert "warnings" in result
    assert any(
        "more than industry standard" in warning for warning in result["warnings"]
    )

    # Verify the specific line 72 condition is triggered
    days_to_expiry = (not_after - now).days
    assert days_to_expiry > 398  # Ensure we're testing the right condition


def test_comprehensive_missing_coverage():
    """Additional comprehensive test to ensure all edge cases are covered."""

    # Test IP address validation with edge cases that might not be covered
    monitor = CertMonitor("test.com")

    # Test various invalid IP formats to ensure line 134 is fully covered
    edge_cases = [
        "192.168.1.1.1",  # Too many octets
        "192.168.1",  # Too few octets
        "192.168.1.-1",  # Negative octet
        "192.168.1.256",  # Octet too large
        "192.168..1",  # Empty octet
        "192.168.1.a",  # Non-numeric octet
        ":::",  # Invalid IPv6
        "gggg::1",  # Invalid IPv6 hex
        "2001:db8::1::2",  # Double :: in IPv6
    ]

    for case in edge_cases:
        result = monitor._is_ip_address(case)
        assert result is False, f"Expected False for {case}"


if __name__ == "__main__":
    pytest.main([__file__])
