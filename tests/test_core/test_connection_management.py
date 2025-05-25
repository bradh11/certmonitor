"""Tests for CertMonitor connection management functionality."""

import socket
from unittest.mock import MagicMock, patch

from certmonitor import CertMonitor


class TestConnectionEstablishment:
    """Test connection establishment and management."""

    def test_connect_already_connected(self):
        """Test connect() returns None when already connected."""
        monitor = CertMonitor("www.example.com")
        monitor.connected = True

        result = monitor.connect()
        assert result is None

    def test_connect_protocol_detection_error(self):
        """Test connect() handles protocol detection errors."""
        monitor = CertMonitor("www.example.com")
        protocol_error = {
            "error": "ProtocolDetectionError",
            "message": "Unable to determine protocol",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(monitor, "detect_protocol", return_value=protocol_error):
            result = monitor.connect()
            assert result == protocol_error

    def test_connect_unsupported_protocol(self):
        """Test connect() handles unsupported protocols."""
        monitor = CertMonitor("www.example.com")

        with patch.object(monitor, "detect_protocol", return_value="unknown"):
            result = monitor.connect()

            assert isinstance(result, dict)
            assert result["error"] == "ProtocolError"
            assert "Unsupported protocol: unknown" in result["message"]

    def test_connect_ssl_handler_creation(self):
        """Test connect() creates SSL handler for SSL protocol."""
        monitor = CertMonitor("www.example.com")

        with patch.object(monitor, "detect_protocol", return_value="ssl"):
            with patch("certmonitor.core.SSLHandler") as mock_ssl_handler:
                mock_handler = MagicMock()
                mock_handler.connect.return_value = None
                mock_ssl_handler.return_value = mock_handler

                result = monitor.connect()

                assert result is None
                assert monitor.connected is True
                assert monitor.handler is mock_handler
                mock_ssl_handler.assert_called_once_with(
                    monitor.host, monitor.port, monitor.error_handler
                )

    def test_connect_ssh_handler_creation(self):
        """Test connect() creates SSH handler for SSH protocol."""
        monitor = CertMonitor("www.example.com")

        with patch.object(monitor, "detect_protocol", return_value="ssh"):
            with patch("certmonitor.core.SSHHandler") as mock_ssh_handler:
                mock_handler = MagicMock()
                mock_handler.connect.return_value = None
                mock_ssh_handler.return_value = mock_handler

                result = monitor.connect()

                assert result is None
                assert monitor.connected is True
                assert monitor.handler is mock_handler
                mock_ssh_handler.assert_called_once_with(
                    monitor.host, monitor.port, monitor.error_handler
                )

    def test_connect_handler_connection_error(self):
        """Test connect() handles handler connection errors."""
        monitor = CertMonitor("www.example.com")
        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(monitor, "detect_protocol", return_value="ssl"):
            with patch("certmonitor.core.SSLHandler") as mock_ssl_handler:
                mock_handler = MagicMock()
                mock_handler.connect.return_value = connection_error
                mock_ssl_handler.return_value = mock_handler

                result = monitor.connect()

                assert result == connection_error
                assert monitor.connected is False


class TestConnectionClosing:
    """Test connection closing functionality."""

    def test_close_with_handler(self):
        """Test close() properly closes handler."""
        monitor = CertMonitor("www.example.com")
        mock_handler = MagicMock()
        monitor.handler = mock_handler

        monitor.close()

        mock_handler.close.assert_called_once()
        assert monitor.handler is None

    def test_close_without_handler(self):
        """Test close() handles None handler gracefully."""
        monitor = CertMonitor("www.example.com")
        monitor.handler = None

        # Should not raise an exception
        monitor.close()
        assert monitor.handler is None


class TestProtocolDetection:
    """Test protocol detection functionality."""

    def test_detect_protocol_ssh(self):
        """Test detect_protocol() correctly identifies SSH."""
        monitor = CertMonitor("www.example.com")

        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"SSH-2.0-OpenSSH"

        with patch("certmonitor.core.socket.create_connection") as mock_create:
            mock_create.return_value.__enter__.return_value = mock_socket

            result = monitor.detect_protocol()
            assert result == "ssh"

    def test_detect_protocol_ssl_handshake(self):
        """Test detect_protocol() correctly identifies SSL by handshake byte."""
        monitor = CertMonitor("www.example.com")

        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"\x16\x03\x01\x00"  # SSL handshake

        with patch("certmonitor.core.socket.create_connection") as mock_create:
            mock_create.return_value.__enter__.return_value = mock_socket

            result = monitor.detect_protocol()
            assert result == "ssl"

    def test_detect_protocol_ssl_alternative_bytes(self):
        """Test detect_protocol() identifies SSL with alternative bytes."""
        monitor = CertMonitor("www.example.com")

        # Test with different first bytes that indicate SSL
        for first_byte in [22, 128, 160]:
            mock_socket = MagicMock()
            mock_socket.recv.return_value = bytes([first_byte, 0, 0, 0])

            with patch("certmonitor.core.socket.create_connection") as mock_create:
                mock_create.return_value.__enter__.return_value = mock_socket

                result = monitor.detect_protocol()
                assert result == "ssl"

    def test_detect_protocol_unknown_data(self):
        """Test detect_protocol() handles unknown protocol data."""
        monitor = CertMonitor("www.example.com")

        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"HTTP/1.1"  # Unknown protocol

        with patch("certmonitor.core.socket.create_connection") as mock_create:
            mock_create.return_value.__enter__.return_value = mock_socket

            result = monitor.detect_protocol()

            assert isinstance(result, dict)
            assert result["error"] == "ProtocolDetectionError"
            assert "Unable to determine protocol" in result["message"]

    def test_detect_protocol_no_data_defaults_ssl(self):
        """Test detect_protocol() defaults to SSL when no data received."""
        monitor = CertMonitor("www.example.com")

        mock_socket = MagicMock()
        mock_socket.recv.side_effect = socket.error("No data")

        with patch("certmonitor.core.socket.create_connection") as mock_create:
            mock_create.return_value.__enter__.return_value = mock_socket

            result = monitor.detect_protocol()
            assert result == "ssl"

    def test_detect_protocol_connection_error(self):
        """Test detect_protocol() handles connection errors."""
        monitor = CertMonitor("www.example.com")

        with patch("certmonitor.core.socket.create_connection") as mock_create:
            mock_create.side_effect = ConnectionError("Connection refused")

            result = monitor.detect_protocol()

            assert isinstance(result, dict)
            assert result["error"] == "ConnectionError"
            assert "Connection refused" in result["message"]


class TestConnectionMaintenance:
    """Test connection maintenance and status checking."""

    def test_ensure_connection_returns_none_on_success(self, cert_monitor):
        """Test that _ensure_connection returns None when already connected."""
        cert_monitor.connected = True
        cert_monitor.handler.check_connection.return_value = True

        result = cert_monitor._ensure_connection()
        assert result is None

    def test_ensure_connection_returns_error_on_failure(self, cert_monitor):
        """Test that _ensure_connection returns error when connection fails."""
        cert_monitor.connected = False
        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(cert_monitor, "connect", return_value=connection_error):
            result = cert_monitor._ensure_connection()
            assert result == connection_error

    def test_ensure_connection_reconnects_on_lost_connection(self, cert_monitor):
        """Test that _ensure_connection reconnects when connection is lost."""
        cert_monitor.connected = True

        # Mock handler.check_connection to raise ConnectionError
        cert_monitor.handler.check_connection.side_effect = ConnectionError(
            "Connection lost"
        )

        with patch.object(cert_monitor, "connect", return_value=None) as mock_connect:
            result = cert_monitor._ensure_connection()

            # Should call connect to reconnect
            mock_connect.assert_called_once()
            assert result is None
            assert (
                cert_monitor.connected is False
            )  # Should be set to False during reconnection
