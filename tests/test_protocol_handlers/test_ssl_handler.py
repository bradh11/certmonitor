# tests/test_protocol_handlers/test_ssl_handler.py

import socket
import ssl
from unittest.mock import MagicMock, patch
import pytest

from certmonitor.protocol_handlers.ssl_handler import SSLHandler
from certmonitor.error_handlers import ErrorHandler


class TestSSLHandler:
    """Test suite for SSLHandler protocol handler."""

    @pytest.fixture
    def error_handler(self):
        """Create a mock error handler."""
        return ErrorHandler()

    @pytest.fixture
    def ssl_handler(self, error_handler):
        """Create an SSLHandler instance for testing."""
        return SSLHandler("test.example.com", 443, error_handler)

    def test_init(self, ssl_handler):
        """Test SSLHandler initialization."""
        assert ssl_handler.host == "test.example.com"
        assert ssl_handler.port == 443
        assert ssl_handler.socket is None
        assert ssl_handler.secure_socket is None
        assert ssl_handler.tls_version is None
        assert isinstance(ssl_handler.error_handler, ErrorHandler)

    def test_get_supported_protocols(self, ssl_handler):
        """Test get_supported_protocols returns available protocols."""
        protocols = ssl_handler.get_supported_protocols()

        # Should return a list of supported protocols
        assert isinstance(protocols, list)
        # At least TLS_CLIENT should be supported in modern Python
        assert ssl.PROTOCOL_TLS_CLIENT in protocols

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_success(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """Test successful SSL connection."""
        # Mock socket connection
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket

        # Mock SSL context and secure socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_secure_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_secure_socket
        mock_secure_socket.version.return_value = "TLSv1.3"

        # Mock get_supported_protocols to return a test protocol
        with patch.object(
            ssl_handler,
            "get_supported_protocols",
            return_value=[ssl.PROTOCOL_TLS_CLIENT],
        ):
            result = ssl_handler.connect()

        # Should return None on success
        assert result is None
        assert ssl_handler.socket == mock_socket
        assert ssl_handler.secure_socket == mock_secure_socket
        assert ssl_handler.tls_version == "TLSv1.3"

    @patch("socket.create_connection")
    def test_connect_socket_error(self, mock_create_connection, ssl_handler):
        """Test connection failure due to socket error."""
        mock_create_connection.side_effect = socket.error("Connection refused")

        with patch.object(
            ssl_handler,
            "get_supported_protocols",
            return_value=[ssl.PROTOCOL_TLS_CLIENT],
        ):
            result = ssl_handler.connect()

        # Should return error dictionary
        assert isinstance(result, dict)
        assert result["error"] == "SSLError"
        assert "Failed to establish SSL connection" in result["message"]

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_ssl_error_with_renegotiation_retry(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """Test SSL connection with renegotiation error and successful retry."""
        # Mock socket connection
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket

        # Mock SSL context
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        # First call raises renegotiation error, second succeeds
        mock_secure_socket = MagicMock()
        mock_secure_socket.version.return_value = "TLSv1.2"
        mock_context.wrap_socket.side_effect = [
            ssl.SSLError("UNSAFE_LEGACY_RENEGOTIATION_DISABLED"),
            mock_secure_socket,
        ]

        with patch.object(
            ssl_handler,
            "get_supported_protocols",
            return_value=[ssl.PROTOCOL_TLS_CLIENT],
        ):
            result = ssl_handler.connect()

        # Should succeed on retry
        assert result is None
        assert ssl_handler.secure_socket == mock_secure_socket
        assert ssl_handler.tls_version == "TLSv1.2"

    def test_fetch_raw_cert_no_connection(self, ssl_handler):
        """Test fetch_raw_cert when no secure socket is established."""
        result = ssl_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "ConnectionError"
        assert "SSL connection not established" in result["message"]

    def test_fetch_raw_cert_success(self, ssl_handler):
        """Test successful certificate fetch."""
        # Mock secure socket
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket

        # Mock certificate data
        mock_der_cert = b"mock_der_certificate_data"
        mock_pem_cert = (
            "-----BEGIN CERTIFICATE-----\nmock_pem_data\n-----END CERTIFICATE-----"
        )
        mock_cert_info = {"subject": {"commonName": "test.example.com"}}

        mock_secure_socket.getpeercert.side_effect = [mock_der_cert, mock_cert_info]

        with patch("ssl.DER_cert_to_PEM_cert", return_value=mock_pem_cert):
            result = ssl_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["der"] == mock_der_cert
        assert result["pem"] == mock_pem_cert
        assert result["cert_info"] == mock_cert_info

    def test_fetch_raw_cert_exception(self, ssl_handler):
        """Test fetch_raw_cert when certificate retrieval fails."""
        # Mock secure socket that raises exception
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket
        mock_secure_socket.getpeercert.side_effect = Exception("Certificate error")

        result = ssl_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "CertificateError"
        assert "Certificate error" in result["message"]

    def test_fetch_raw_cipher_no_connection(self, ssl_handler):
        """Test fetch_raw_cipher when no secure socket is established."""
        result = ssl_handler.fetch_raw_cipher()

        assert isinstance(result, dict)
        assert result["error"] == "ConnectionError"
        assert "SSL connection not established" in result["message"]

    def test_fetch_raw_cipher_success(self, ssl_handler):
        """Test successful cipher information fetch."""
        # Mock secure socket
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket

        # Mock cipher data
        cipher_data = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.3", 128)
        mock_secure_socket.cipher.return_value = cipher_data

        result = ssl_handler.fetch_raw_cipher()

        assert result == cipher_data

    def test_check_connection_no_socket(self, ssl_handler):
        """Test check_connection when no secure socket exists."""
        result = ssl_handler.check_connection()
        assert result is False

    def test_check_connection_success(self, ssl_handler):
        """Test successful connection check."""
        # Mock secure socket
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket
        mock_secure_socket.getpeername.return_value = ("192.168.1.1", 443)

        result = ssl_handler.check_connection()
        assert result is True

    def test_check_connection_exception(self, ssl_handler):
        """Test connection check when socket raises exception."""
        # Mock secure socket that raises exception
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket
        mock_secure_socket.getpeername.side_effect = Exception("Connection lost")

        with patch("logging.error") as mock_log:
            result = ssl_handler.check_connection()

        assert result is False
        mock_log.assert_called_once()

    def test_close(self, ssl_handler):
        """Test close method properly cleans up connections."""
        # Mock sockets
        mock_socket = MagicMock()
        mock_secure_socket = MagicMock()
        ssl_handler.socket = mock_socket
        ssl_handler.secure_socket = mock_secure_socket
        ssl_handler.tls_version = "TLSv1.3"

        ssl_handler.close()

        # Verify sockets are closed and attributes reset
        mock_secure_socket.close.assert_called_once()
        mock_socket.close.assert_called_once()
        assert ssl_handler.secure_socket is None
        assert ssl_handler.socket is None
        assert ssl_handler.tls_version is None

    def test_close_partial_cleanup(self, ssl_handler):
        """Test close method with only secure socket."""
        # Mock only secure socket
        mock_secure_socket = MagicMock()
        ssl_handler.secure_socket = mock_secure_socket
        ssl_handler.tls_version = "TLSv1.2"

        ssl_handler.close()

        mock_secure_socket.close.assert_called_once()
        assert ssl_handler.secure_socket is None
        assert ssl_handler.socket is None
        assert ssl_handler.tls_version is None

    def test_get_protocol_version_with_version(self, ssl_handler):
        """Test get_protocol_version when TLS version is available."""
        ssl_handler.tls_version = "TLSv1.3"

        result = ssl_handler.get_protocol_version()
        assert result == "TLSv1.3"

    def test_get_protocol_version_unknown(self, ssl_handler):
        """Test get_protocol_version when TLS version is not available."""
        result = ssl_handler.get_protocol_version()
        assert result == "Unknown"

    @patch("warnings.catch_warnings")
    def test_get_supported_protocols_with_deprecation_warnings(
        self, mock_warnings, ssl_handler
    ):
        """Test that get_supported_protocols properly handles deprecation warnings."""
        with patch("ssl.SSLContext") as mock_ssl_context:
            # Some protocols should create contexts successfully
            mock_ssl_context.return_value = MagicMock()

            protocols = ssl_handler.get_supported_protocols()

            # Should have called warnings context manager
            assert mock_warnings.called
            assert isinstance(protocols, list)

    def test_get_supported_protocols_with_attribute_error(self, ssl_handler):
        """Test get_supported_protocols handles AttributeError for unsupported protocols."""
        # Get the actual list length to provide enough side effects
        actual_protocols = [
            ssl.PROTOCOL_TLS_CLIENT,
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_SSLv23,
        ]

        with patch("ssl.SSLContext") as mock_ssl_context:
            # Create side effects that match the number of protocols
            side_effects = []
            for i, protocol in enumerate(actual_protocols):
                if i == 1:  # Second protocol fails
                    side_effects.append(AttributeError("Protocol not supported"))
                else:
                    side_effects.append(MagicMock())

            mock_ssl_context.side_effect = side_effects

            protocols = ssl_handler.get_supported_protocols()

            # Should only include protocols that didn't raise AttributeError
            assert (
                len(protocols) == len(actual_protocols) - 1
            )  # One less due to AttributeError

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_multiple_protocol_attempts(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """Test connect trying multiple protocols when first ones fail."""
        # Mock socket connection
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket

        # Mock SSL context
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        # First protocol fails, second succeeds
        mock_secure_socket = MagicMock()
        mock_secure_socket.version.return_value = "TLSv1.2"
        mock_context.wrap_socket.side_effect = [
            ssl.SSLError("Protocol not supported"),
            mock_secure_socket,
        ]

        # Mock multiple protocols available
        test_protocols = [ssl.PROTOCOL_TLS_CLIENT, ssl.PROTOCOL_TLSv1_2]
        with patch.object(
            ssl_handler, "get_supported_protocols", return_value=test_protocols
        ):
            result = ssl_handler.connect()

        # Should succeed with second protocol
        assert result is None
        assert ssl_handler.secure_socket == mock_secure_socket

    def test_connect_all_protocols_fail(self, ssl_handler):
        """Test connect when all protocols fail."""
        with patch.object(
            ssl_handler,
            "get_supported_protocols",
            return_value=[ssl.PROTOCOL_TLS_CLIENT],
        ):
            with patch(
                "socket.create_connection", side_effect=Exception("Connection failed")
            ):
                result = ssl_handler.connect()

        assert isinstance(result, dict)
        assert result["error"] == "SSLError"
        assert "Failed to establish SSL connection" in result["message"]

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_socket_cleanup_on_failure(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """Test that socket is properly cleaned up when SSL connection fails."""
        # Mock socket connection
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket

        # Mock SSL context that fails
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.side_effect = Exception("SSL handshake failed")

        with patch.object(
            ssl_handler,
            "get_supported_protocols",
            return_value=[ssl.PROTOCOL_TLS_CLIENT],
        ):
            result = ssl_handler.connect()

        # Should have attempted to close the socket
        mock_socket.close.assert_called()
        assert isinstance(result, dict)
        assert result["error"] == "SSLError"
