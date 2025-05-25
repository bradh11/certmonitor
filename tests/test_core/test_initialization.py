# tests/test_core/test_initialization.py

"""Tests for CertMonitor initialization and context manager functionality."""

from unittest.mock import MagicMock, patch

from certmonitor import CertMonitor


class TestCertMonitorInitialization:
    """Test CertMonitor initialization and basic setup."""

    def test_init(self):
        """Test basic CertMonitor initialization."""
        monitor = CertMonitor("example.com", 8443, ["expiration", "hostname"])
        assert monitor.host == "example.com"
        assert monitor.port == 8443
        assert monitor.enabled_validators == ["expiration", "hostname"]
        assert not monitor.is_ip

    def test_is_ip_address(self):
        """Test IP address detection during initialization."""
        assert CertMonitor("192.168.1.1").is_ip
        assert not CertMonitor("example.com").is_ip

    def test_initialization_with_default_validators(self):
        """Test initialization uses default validators when None provided."""
        with patch(
            "certmonitor.core.config.ENABLED_VALIDATORS", ["default1", "default2"]
        ):
            # Test that empty list triggers fallback to config.ENABLED_VALIDATORS
            monitor = CertMonitor("www.example.com", enabled_validators=[])
            # The implementation uses: enabled_validators or config.ENABLED_VALIDATORS
            assert monitor.enabled_validators == ["default1", "default2"]

    def test_initialization_with_empty_list(self):
        """Test initialization with empty validator list."""
        monitor = CertMonitor("www.example.com", enabled_validators=[])
        assert monitor.enabled_validators == []

    def test_is_ip_address_ipv6(self):
        """Test _is_ip_address() correctly identifies IPv6 addresses."""
        assert CertMonitor("2001:db8::1").is_ip
        assert CertMonitor("::1").is_ip  # localhost IPv6
        assert CertMonitor("fe80::1").is_ip  # link-local IPv6

    def test_is_ip_address_invalid(self):
        """Test _is_ip_address method with invalid IP addresses to cover line 134."""
        monitor = CertMonitor("example.com")

        # Test cases that should trigger ValueError exception
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
            # This should hit the except ValueError block
            result = monitor._is_ip_address(invalid_input)
            assert result is False

    def test_is_ip_address_exception_coverage(self):
        """Test _is_ip_address with values that raise ValueError to specifically cover line 134."""
        monitor = CertMonitor("example.com")

        # These should all trigger the ValueError exception and return False
        assert monitor._is_ip_address("not.an.ip") is False
        assert monitor._is_ip_address("300.300.300.300") is False
        assert monitor._is_ip_address("incomplete.ip") is False

    def test_ip_address_exception_handling(self):
        """Test _is_ip_address exception handling to ensure comprehensive coverage."""
        monitor = CertMonitor("example.com")

        # Test cases that should trigger ValueError exception
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
            # This should hit the except ValueError block
            result = monitor._is_ip_address(invalid_input)
            assert result is False

    def test_ip_address_exception_with_mock(self):
        """Test _is_ip_address exception handling with mock to ensure coverage."""
        monitor = CertMonitor("test.com")

        # Create a mock that raises ValueError when ipaddress.ip_address is called
        with patch("certmonitor.core.ipaddress.ip_address") as mock_ip_address:
            mock_ip_address.side_effect = ValueError("Invalid IP address")

            # This should trigger the except ValueError block
            result = monitor._is_ip_address("invalid.input")
            assert result is False

            # Verify ipaddress.ip_address was called
            mock_ip_address.assert_called_once_with("invalid.input")

    def test_is_ip_address_with_invalid_input(self):
        """Test _is_ip_address method with invalid input to cover line 134."""
        monitor = CertMonitor("example.com")

        # Test with clearly invalid IP inputs that should raise ValueError
        assert monitor._is_ip_address("clearly.not.an.ip") is False
        assert monitor._is_ip_address("999.999.999.999") is False
        assert monitor._is_ip_address("incomplete") is False


class TestContextManager:
    """Test CertMonitor context manager functionality."""

    def test_context_manager_enter(self):
        """Test that __enter__ calls connect and returns self."""
        monitor = CertMonitor("www.example.com")

        with patch.object(monitor, "connect") as mock_connect:
            result = monitor.__enter__()

            mock_connect.assert_called_once()
            assert result is monitor

    def test_context_manager_exit(self):
        """Test that __exit__ calls close regardless of exception type."""
        monitor = CertMonitor("www.example.com")

        with patch.object(monitor, "close") as mock_close:
            # Test normal exit
            monitor.__exit__(None, None, None)
            mock_close.assert_called_once()

            # Reset mock
            mock_close.reset_mock()

            # Test exit with exception
            monitor.__exit__(Exception, Exception("test"), None)
            mock_close.assert_called_once()

    def test_context_manager_full_workflow(self):
        """Test complete context manager workflow."""
        with patch("certmonitor.core.socket.create_connection") as mock_socket:
            mock_socket.return_value.__enter__.return_value.recv.return_value = (
                b"\x16\x03\x01"  # SSL handshake
            )

            with patch("certmonitor.core.SSLHandler") as mock_ssl_handler:
                mock_handler = MagicMock()
                mock_handler.connect.return_value = None
                mock_ssl_handler.return_value = mock_handler

                with CertMonitor("www.example.com") as monitor:
                    assert monitor.connected is True
                    assert monitor.protocol == "ssl"
                    assert monitor.handler is mock_handler

                # Verify close was called
                mock_handler.close.assert_called_once()
