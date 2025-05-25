"""Tests to cover missing lines in protocol handlers."""

from unittest.mock import MagicMock, patch
import ssl
import socket
import pytest

from certmonitor.protocol_handlers.base import BaseProtocolHandler
from certmonitor.protocol_handlers.ssl_handler import SSLHandler


class ConcreteHandler(BaseProtocolHandler):
    """Concrete implementation of BaseProtocolHandler for testing."""

    def connect(self):
        """Test implementation."""
        pass

    def fetch_raw_cert(self):
        """Test implementation."""
        pass

    def close(self):
        """Test implementation."""
        pass


def test_base_handler_abstract_methods():
    """Test that BaseProtocolHandler abstract methods can be implemented."""
    # This covers lines 16, 20, 24 in base.py
    handler = ConcreteHandler("example.com", 443, None)

    # Call abstract methods to ensure they are callable
    handler.connect()
    handler.fetch_raw_cert()
    handler.close()

    # Verify base attributes are set
    assert handler.host == "example.com"
    assert handler.port == 443
    assert handler.error_handler is None


def test_ssl_handler_unsafe_legacy_renegotiation_error():
    """Test SSL handler handles unsafe legacy renegotiation error to cover lines 70-71."""
    # Create a mock error handler
    mock_error_handler = MagicMock()
    mock_error_handler.handle_error.return_value = {"error": "SSL Error"}

    handler = SSLHandler("example.com", 443, mock_error_handler)

    # Mock socket creation
    mock_socket = MagicMock()

    with patch("socket.create_connection", return_value=mock_socket):
        with patch("ssl.SSLContext") as mock_ssl_context_class:
            mock_ssl_context = MagicMock()
            mock_ssl_context_class.return_value = mock_ssl_context

            # Mock the first wrap_socket to raise an SSL error with unsafe legacy renegotiation
            ssl_error = ssl.SSLError("UNSAFE_LEGACY_RENEGOTIATION_DISABLED")

            # First wrap_socket call raises UNSAFE_LEGACY_RENEGOTIATION_DISABLED
            # Second wrap_socket call (retry) raises another exception to cover lines 70-71
            mock_ssl_context.wrap_socket.side_effect = [
                ssl_error,  # First call fails with unsafe legacy renegotiation
                Exception("Second SSL Error"),  # Second call fails to cover lines 70-71
            ]

            with patch("logging.error") as mock_log:
                result = handler.connect()

                # Should call the logging.error on line 70-71
                mock_log.assert_called()

                # Should return error response from error handler
                assert result == {"error": "SSL Error"}


def test_ssl_handler_socket_close_on_exception():
    """Test SSL handler closes socket on exception."""
    # Create a mock error handler
    mock_error_handler = MagicMock()
    mock_error_handler.handle_error.return_value = {"error": "SSL Error"}

    handler = SSLHandler("example.com", 443, mock_error_handler)

    # Mock socket creation
    mock_socket = MagicMock()

    with patch("socket.create_connection", return_value=mock_socket):
        with patch("ssl.SSLContext") as mock_ssl_context_class:
            mock_ssl_context = MagicMock()
            mock_ssl_context_class.return_value = mock_ssl_context

            # Both wrap_socket calls fail to trigger exception handling
            mock_ssl_context.wrap_socket.side_effect = Exception("SSL Error")

            result = handler.connect()

            # Should close the socket and handle the error
            mock_socket.close.assert_called()
            assert result == {"error": "SSL Error"}
