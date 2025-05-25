import socket
from unittest.mock import MagicMock, patch

from certmonitor.error_handlers import ErrorHandler
from certmonitor.protocol_handlers.ssh_handler import SSHHandler


class TestSSHHandler:
    """Test suite for SSHHandler protocol handler."""

    def test_init(self):
        """Test SSHHandler initialization."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        assert ssh_handler.host == "test.example.com"
        assert ssh_handler.port == 22
        assert ssh_handler.socket is None
        assert isinstance(ssh_handler.error_handler, ErrorHandler)

    @patch("socket.create_connection")
    def test_connect_success(self, mock_create_connection):
        """Test successful SSH connection."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket

        result = ssh_handler.connect()

        # Should return None on success and set socket
        assert result is None
        assert ssh_handler.socket == mock_socket
        mock_create_connection.assert_called_once_with(
            ("test.example.com", 22), timeout=10
        )

    @patch("socket.create_connection")
    def test_connect_socket_error(self, mock_create_connection):
        """Test connection failure due to socket error."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_create_connection.side_effect = socket.error("Connection refused")

        result = ssh_handler.connect()

        assert isinstance(result, dict)
        assert result["error"] == "SocketError"
        assert "Connection refused" in result["message"]
        assert result["host"] == "test.example.com"
        assert result["port"] == 22

    @patch("socket.create_connection")
    def test_connect_generic_exception(self, mock_create_connection):
        """Test connection failure due to generic exception."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_create_connection.side_effect = Exception("Unexpected error")

        result = ssh_handler.connect()

        assert isinstance(result, dict)
        assert result["error"] == "UnknownError"
        assert "Unexpected error" in result["message"]
        assert result["host"] == "test.example.com"
        assert result["port"] == 22

    def test_fetch_raw_cert_valid_ssh_banner(self):
        """Test fetch_raw_cert with valid SSH banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock SSH-2.0 banner
        mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["protocol"] == "ssh"
        assert result["ssh_version_string"] == "SSH-2.0-OpenSSH_8.9"
        assert result["protocol_version"] == "2.0"
        assert result["software_version"] == "OpenSSH_8.9"

    def test_fetch_raw_cert_ssh_1_99_banner(self):
        """Test fetch_raw_cert with SSH 1.99 banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock SSH-1.99 banner
        mock_socket.recv.return_value = b"SSH-1.99-Cisco-1.25"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["protocol"] == "ssh"
        assert result["ssh_version_string"] == "SSH-1.99-Cisco-1.25"
        assert result["protocol_version"] == "1.99"
        assert result["software_version"] == "Cisco-1.25"

    def test_fetch_raw_cert_invalid_banner(self):
        """Test fetch_raw_cert with invalid SSH banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock invalid banner
        mock_socket.recv.return_value = b"INVALID BANNER"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "SSHError"
        assert "Invalid SSH banner" in result["message"]
        assert result["host"] == "test.example.com"
        assert result["port"] == 22

    def test_fetch_raw_cert_socket_exception(self):
        """Test fetch_raw_cert with socket exception."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock socket exception
        mock_socket.recv.side_effect = socket.error("Connection reset")

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "SSHError"
        assert "Connection reset" in result["message"]
        assert result["host"] == "test.example.com"
        assert result["port"] == 22

    def test_fetch_raw_cert_decode_error(self):
        """Test fetch_raw_cert with non-ASCII banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock banner with non-ASCII characters that will be ignored
        mock_socket.recv.return_value = b"SSH-2.0-\xff\xfeOpenSSH_8.9"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["protocol"] == "ssh"
        assert "SSH-2.0-OpenSSH_8.9" in result["ssh_version_string"]
        assert result["protocol_version"] == "2.0"

    def test_close_with_socket(self):
        """Test close method when socket exists."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        ssh_handler.close()

        mock_socket.close.assert_called_once()

    def test_close_without_socket(self):
        """Test close method when socket is None."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        # Ensure socket is None
        ssh_handler.socket = None

        # Should not raise exception
        ssh_handler.close()

    def test_check_connection_success(self):
        """Test check_connection when connection is active."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock successful getpeername call
        mock_socket.getpeername.return_value = ("192.168.1.1", 22)

        result = ssh_handler.check_connection()

        assert result is True
        mock_socket.getpeername.assert_called_once()

    def test_check_connection_failure(self):
        """Test check_connection when connection is lost."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock socket error on getpeername call
        mock_socket.getpeername.side_effect = socket.error("Connection lost")

        result = ssh_handler.check_connection()

        assert result is False
        mock_socket.getpeername.assert_called_once()

    def test_check_connection_no_socket(self):
        """Test check_connection when socket is None."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        # Ensure socket is None
        ssh_handler.socket = None

        result = ssh_handler.check_connection()

        assert result is False

    def test_fetch_raw_cert_empty_banner(self):
        """Test fetch_raw_cert with empty banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock empty banner
        mock_socket.recv.return_value = b""

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "SSHError"
        assert "Invalid SSH banner" in result["message"]

    def test_fetch_raw_cert_whitespace_only(self):
        """Test fetch_raw_cert with whitespace-only banner."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock whitespace-only banner
        mock_socket.recv.return_value = b"   \r\n"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "SSHError"
        assert "Invalid SSH banner" in result["message"]

    def test_fetch_raw_cert_complex_software_version(self):
        """Test fetch_raw_cert with complex software version."""
        error_handler = ErrorHandler()
        ssh_handler = SSHHandler("test.example.com", 22, error_handler)

        mock_socket = MagicMock()
        ssh_handler.socket = mock_socket

        # Mock SSH banner with complex software version
        mock_socket.recv.return_value = b"SSH-2.0-libssh_0.6.3-complex.version-1.2.3"

        result = ssh_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["protocol"] == "ssh"
        assert (
            result["ssh_version_string"] == "SSH-2.0-libssh_0.6.3-complex.version-1.2.3"
        )
        assert result["protocol_version"] == "2.0"
        assert result["software_version"] == "libssh_0.6.3-complex.version-1.2.3"
