"""Tests for CertMonitor raw certificate data operations."""

from unittest.mock import MagicMock, patch

from certmonitor.core import CertMonitor


class TestRawDataRetrieval:
    """Test raw certificate data retrieval methods."""

    def test_get_raw_der_error_from_handler(self):
        """Test get_raw_der when handler returns an error response."""
        monitor = CertMonitor("example.com")
        monitor.protocol = "ssl"  # Set SSL protocol to avoid protocol error
        monitor.der = None

        # Mock _ensure_connection to return None (successful connection)
        with patch.object(monitor, "_ensure_connection", return_value=None):
            # Mock handler.fetch_raw_cert to return an error
            monitor.handler = MagicMock()
            monitor.handler.fetch_raw_cert.return_value = {"error": "Handler error"}

            result = monitor.get_raw_der()
            assert result == {"error": "Handler error"}

    def test_get_raw_pem_error_from_handler(self):
        """Test get_raw_pem when handler returns an error response."""
        monitor = CertMonitor("example.com")
        monitor.protocol = "ssl"  # Set SSL protocol to avoid protocol error
        monitor.pem = None

        # Mock _ensure_connection to return None (success)
        with patch.object(monitor, "_ensure_connection", return_value=None):
            # Mock handler.fetch_raw_cert to return an error
            monitor.handler = MagicMock()
            monitor.handler.fetch_raw_cert.return_value = {"error": "Handler error"}

            result = monitor.get_raw_pem()
            assert result == {"error": "Handler error"}

    def test_get_raw_der_handler_none_after_ensure_connection(self):
        """Test get_raw_der when handler becomes None after _ensure_connection."""
        monitor = CertMonitor("example.com")
        monitor.protocol = "ssl"
        monitor.der = None

        # Mock _ensure_connection to return None (success) but handler stays None
        with patch.object(monitor, "_ensure_connection", return_value=None):
            monitor.handler = None  # Explicitly set handler to None

            result = monitor.get_raw_der()
            assert isinstance(result, dict)
            assert "error" in result
            assert "ConnectionError" == result["error"]

    def test_get_raw_pem_handler_none_after_ensure_connection(self):
        """Test get_raw_pem when handler becomes None after _ensure_connection."""
        monitor = CertMonitor("example.com")
        monitor.protocol = "ssl"
        monitor.pem = None

        # Mock _ensure_connection to return None (success) but handler stays None
        with patch.object(monitor, "_ensure_connection", return_value=None):
            monitor.handler = None  # Explicitly set handler to None

            result = monitor.get_raw_pem()
            assert isinstance(result, dict)
            assert "error" in result
            assert "ConnectionError" == result["error"]
