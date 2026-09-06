# tests/test_protocol_handlers/test_ssl_handler.py

import ssl
from unittest.mock import MagicMock, patch

import pytest

from certmonitor.error_handlers import ErrorHandler
from certmonitor.protocol_handlers.ssl_handler import SSLHandler


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

    def test_context_is_permissive_and_warning_free(self, ssl_handler):
        """The collection context opens the version range without deprecated constants."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            context = ssl_handler._build_context()
        assert context.check_hostname is False
        assert context.verify_mode == ssl.CERT_NONE
        assert context.minimum_version == ssl.TLSVersion.MINIMUM_SUPPORTED
        assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
        capped = ssl_handler._build_context(maximum_version=ssl.TLSVersion.TLSv1_2)
        assert capped.maximum_version == ssl.TLSVersion.TLSv1_2

    def test_collector_does_not_touch_global_warning_filters(self):
        """Regression guard for #67: concurrent scans must not mutate warnings state."""
        import inspect

        import certmonitor.protocol_handlers.ssl_handler as module

        assert "catch_warnings" not in inspect.getsource(module)

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_success(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """A successful handshake stores the sockets and negotiated version."""
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_secure_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_secure_socket
        mock_secure_socket.version.return_value = "TLSv1.3"

        assert ssl_handler.connect() is None
        assert ssl_handler.socket is None  # the TLS socket owns the connection
        assert ssl_handler.secure_socket == mock_secure_socket
        assert ssl_handler.tls_version == "TLSv1.3"
        mock_create_connection.assert_called_once_with(
            ("test.example.com", 443), timeout=10.0
        )

    @patch("socket.create_connection")
    def test_connect_socket_error(self, mock_create_connection, ssl_handler):
        """Connection refused on every attempt yields the SSLError dict."""
        mock_create_connection.side_effect = OSError("Connection refused")
        result = ssl_handler.connect()
        assert isinstance(result, dict)
        assert result["error"] == "SSLError"
        assert "Failed to establish SSL connection" in result["message"]
        assert mock_create_connection.call_count == 2  # full range, then TLS 1.2 cap

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_retries_with_legacy_server_connect(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """A legacy-renegotiation refusal is retried once with the legacy option."""
        mock_create_connection.return_value = MagicMock()
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_secure_socket = MagicMock()
        mock_secure_socket.version.return_value = "TLSv1.2"
        mock_context.wrap_socket.side_effect = [
            ssl.SSLError("UNSAFE_LEGACY_RENEGOTIATION_DISABLED"),
            mock_secure_socket,
        ]
        with patch.object(
            ssl_handler, "_build_context", wraps=ssl_handler._build_context
        ) as build:
            assert ssl_handler.connect() is None
        assert ssl_handler.tls_version == "TLSv1.2"
        assert build.call_args_list[1].kwargs["legacy_server_connect"] is True

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_caps_at_tls12_when_full_range_fails(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """A server that rejects the full-range hello is retried with a TLS 1.2 cap."""
        mock_create_connection.return_value = MagicMock()
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_secure_socket = MagicMock()
        mock_secure_socket.version.return_value = "TLSv1.2"
        mock_context.wrap_socket.side_effect = [
            ssl.SSLError("wrong version number"),
            mock_secure_socket,
        ]
        with patch.object(
            ssl_handler, "_build_context", wraps=ssl_handler._build_context
        ) as build:
            assert ssl_handler.connect() is None
        assert build.call_args_list[1].kwargs == {
            "maximum_version": ssl.TLSVersion.TLSv1_2
        }

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

    def test_fetch_raw_cert_none_certificate(self, ssl_handler):
        """Test fetch_raw_cert when getpeercert returns None."""
        ssl_handler.secure_socket = MagicMock()

        # Mock getpeercert to return None
        ssl_handler.secure_socket.getpeercert.return_value = None

        result = ssl_handler.fetch_raw_cert()

        assert isinstance(result, dict)
        assert result["error"] == "CertificateError"
        assert "No certificate available" in result["message"]

    def test_fetch_raw_cert_chain_via_public_api(self, ssl_handler):
        """3.13+ path: get_verified_chain returns List[bytes]."""
        mock_secure_socket = MagicMock(spec=["getpeercert", "get_verified_chain"])
        ssl_handler.secure_socket = mock_secure_socket

        leaf_der = b"leaf_der_bytes"
        chain_ders = [leaf_der, b"intermediate_der", b"root_der"]
        mock_secure_socket.getpeercert.side_effect = [
            leaf_der,
            {"subject": {"commonName": "test"}},
        ]
        mock_secure_socket.get_verified_chain.return_value = chain_ders

        with patch("ssl.DER_cert_to_PEM_cert", return_value="pem"):
            result = ssl_handler.fetch_raw_cert()

        assert result["chain_der"] == chain_ders
        assert result["chain_error"] is None
        mock_secure_socket.get_verified_chain.assert_called_once()

    def test_fetch_raw_cert_chain_via_sslobj_fallback(self, ssl_handler):
        """3.10–3.12 path: _sslobj.get_unverified_chain + PEM→DER conversion."""
        mock_secure_socket = MagicMock(spec=["getpeercert", "_sslobj"])
        ssl_handler.secure_socket = mock_secure_socket

        leaf_der = b"leaf_der_bytes"
        mock_secure_socket.getpeercert.side_effect = [
            leaf_der,
            {"subject": {"commonName": "test"}},
        ]

        fake_cert_a = MagicMock()
        fake_cert_a.public_bytes.return_value = "PEM_A"
        fake_cert_b = MagicMock()
        fake_cert_b.public_bytes.return_value = "PEM_B"
        mock_secure_socket._sslobj = MagicMock(spec=["get_unverified_chain"])
        mock_secure_socket._sslobj.get_unverified_chain.return_value = [
            fake_cert_a,
            fake_cert_b,
        ]

        with (
            patch("ssl.DER_cert_to_PEM_cert", return_value="pem"),
            patch("ssl.PEM_cert_to_DER_cert", side_effect=[b"DER_A", b"DER_B"]),
        ):
            result = ssl_handler.fetch_raw_cert()

        assert result["chain_der"] == [b"DER_A", b"DER_B"]
        assert result["chain_error"] is None

    def test_fetch_raw_cert_chain_unavailable(self, ssl_handler):
        """Defensive path: neither public API nor _sslobj.get_unverified_chain.

        Every supported interpreter (3.10+) exposes at least one of these, so
        this branch is not reachable in practice, but the handler degrades
        gracefully to the leaf cert with an informative error if it ever is.
        """
        mock_secure_socket = MagicMock(spec=["getpeercert"])
        ssl_handler.secure_socket = mock_secure_socket

        leaf_der = b"leaf_der_bytes"
        mock_secure_socket.getpeercert.side_effect = [
            leaf_der,
            {"subject": {"commonName": "test"}},
        ]

        with patch("ssl.DER_cert_to_PEM_cert", return_value="pem"):
            result = ssl_handler.fetch_raw_cert()

        assert result["chain_der"] is None
        assert "not available on this interpreter" in result["chain_error"]

    def test_fetch_raw_cert_chain_public_api_exception(self, ssl_handler):
        mock_secure_socket = MagicMock(spec=["getpeercert", "get_verified_chain"])
        ssl_handler.secure_socket = mock_secure_socket
        mock_secure_socket.getpeercert.side_effect = [
            b"leaf",
            {"subject": {"commonName": "test"}},
        ]
        mock_secure_socket.get_verified_chain.side_effect = RuntimeError("boom")

        with patch("ssl.DER_cert_to_PEM_cert", return_value="pem"):
            result = ssl_handler.fetch_raw_cert()

        assert result["chain_der"] is None
        assert "Failed to retrieve certificate chain" in result["chain_error"]
        assert "boom" in result["chain_error"]

    def test_fetch_raw_cert_chain_sslobj_exception(self, ssl_handler):
        mock_secure_socket = MagicMock(spec=["getpeercert", "_sslobj"])
        ssl_handler.secure_socket = mock_secure_socket
        mock_secure_socket.getpeercert.side_effect = [
            b"leaf",
            {"subject": {"commonName": "test"}},
        ]
        mock_secure_socket._sslobj = MagicMock(spec=["get_unverified_chain"])
        mock_secure_socket._sslobj.get_unverified_chain.side_effect = RuntimeError(
            "sslobj boom"
        )

        with patch("ssl.DER_cert_to_PEM_cert", return_value="pem"):
            result = ssl_handler.fetch_raw_cert()

        assert result["chain_der"] is None
        assert "sslobj boom" in result["chain_error"]

    def test_fetch_chain_der_no_secure_socket(self, ssl_handler):
        """Direct call with no connection returns an error tuple."""
        chain, error = ssl_handler._fetch_chain_der()
        assert chain is None
        assert error == "SSL connection not established"

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

    def test_fetch_raw_cipher_none_cipher_info(self, ssl_handler):
        """Test fetch_raw_cipher when cipher returns None."""
        ssl_handler.secure_socket = MagicMock()

        # Mock cipher to return None
        ssl_handler.secure_socket.cipher.return_value = None

        result = ssl_handler.fetch_raw_cipher()

        assert isinstance(result, dict)
        assert result["error"] == "CipherError"
        assert "No cipher information available" in result["message"]

    def test_fetch_raw_cipher_invalid_tuple_length(self, ssl_handler):
        """Test fetch_raw_cipher when cipher returns tuple with wrong length."""
        ssl_handler.secure_socket = MagicMock()

        # Mock cipher to return tuple with wrong length (should be 3-tuple)
        ssl_handler.secure_socket.cipher.return_value = (
            "TLS",
            "v1.2",
        )  # Only 2 elements

        result = ssl_handler.fetch_raw_cipher()

        assert isinstance(result, dict)
        assert result["error"] == "CipherError"
        assert "Cipher information is not a tuple" in result["message"]

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

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_connect_socket_cleanup_on_failure(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """Every failed attempt closes its socket."""
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.side_effect = Exception("SSL handshake failed")

        result = ssl_handler.connect()
        assert mock_socket.close.call_count == 2
        assert ssl_handler.socket is None
        assert isinstance(result, dict)
        assert result["error"] == "SSLError"

    @patch("socket.create_connection")
    @patch("ssl.SSLContext")
    def test_legacy_retry_failure_falls_through(
        self, mock_ssl_context, mock_create_connection, ssl_handler
    ):
        """If the legacy retry also fails, the TLS 1.2 attempt still runs, then the error dict."""
        mock_create_connection.return_value = MagicMock()
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.side_effect = [
            ssl.SSLError("unsafe legacy renegotiation disabled"),
            ssl.SSLError("still refused"),
            ssl.SSLError("wrong version number"),
        ]
        result = ssl_handler.connect()
        assert isinstance(result, dict)
        assert result["error"] == "SSLError"
        assert mock_context.wrap_socket.call_count == 3
