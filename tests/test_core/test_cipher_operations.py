"""Tests for CertMonitor cipher operations and TLS protocol information."""

import pytest
from unittest.mock import patch, MagicMock
from certmonitor.core import CertMonitor


class TestRawCipherOperations:
    """Test raw cipher fetching and processing."""

    def test_fetch_raw_cipher_success(self):
        """Test _fetch_raw_cipher() successful execution."""
        monitor = CertMonitor("www.example.com")
        monitor.protocol = "ssl"
        mock_cipher = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)

        mock_handler = MagicMock()
        mock_handler.fetch_raw_cipher.return_value = mock_cipher
        monitor.handler = mock_handler

        with patch.object(monitor, "_ensure_connection", return_value=None):
            result = monitor._fetch_raw_cipher()
            assert result == mock_cipher

    def test_fetch_raw_cipher_non_ssl_protocol(self):
        """Test _fetch_raw_cipher() handles non-SSL protocols."""
        monitor = CertMonitor("www.example.com")
        monitor.protocol = "ssh"

        with patch.object(monitor, "_ensure_connection", return_value=None):
            result = monitor._fetch_raw_cipher()

            assert isinstance(result, dict)
            assert result["error"] == "ProtocolError"
            assert (
                "Cipher information is only available for SSL/TLS connections"
                in result["message"]
            )

    def test_fetch_raw_cipher_connection_error(self):
        """Test _fetch_raw_cipher() handles connection errors."""
        monitor = CertMonitor("www.example.com")
        monitor.protocol = "ssl"

        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(monitor, "_ensure_connection", return_value=connection_error):
            result = monitor._fetch_raw_cipher()
            assert result == connection_error


class TestCipherInfoOperations:
    """Test cipher information retrieval and formatting."""

    def test_get_cipher_info_success(self):
        """Test get_cipher_info() successful execution."""
        monitor = CertMonitor("www.example.com")
        mock_cipher = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)

        with patch.object(monitor, "_fetch_raw_cipher", return_value=mock_cipher):
            with patch("certmonitor.core.parse_cipher_suite") as mock_parse:
                mock_parse.return_value = {
                    "encryption": "AES128-GCM",
                    "mac": "SHA256",
                    "key_exchange": "ECDHE-RSA",
                }

                result = monitor.get_cipher_info()

                assert isinstance(result, dict)
                assert "cipher_suite" in result
                assert "protocol_version" in result
                assert "key_bit_length" in result
                assert result["protocol_version"] == "TLSv1.2"
                assert result["key_bit_length"] == 128

    def test_get_cipher_info_tls13_special_handling(self):
        """Test get_cipher_info() special handling for TLS 1.3."""
        monitor = CertMonitor("www.example.com")
        mock_cipher = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

        with patch.object(monitor, "_fetch_raw_cipher", return_value=mock_cipher):
            with patch("certmonitor.core.parse_cipher_suite") as mock_parse:
                mock_parse.return_value = {
                    "encryption": "AES128-GCM",
                    "mac": "SHA256",
                    "key_exchange": "ECDHE",
                }

                result = monitor.get_cipher_info()

                assert "key_exchange_algorithm" in result["cipher_suite"]
                assert (
                    "Not applicable" in result["cipher_suite"]["key_exchange_algorithm"]
                )

    def test_get_cipher_info_error_response(self):
        """Test get_cipher_info() handles error responses from _fetch_raw_cipher."""
        monitor = CertMonitor("www.example.com")
        cipher_error = {
            "error": "ConnectionError",
            "message": "Failed to get cipher",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(monitor, "_fetch_raw_cipher", return_value=cipher_error):
            result = monitor.get_cipher_info()
            assert result == cipher_error

    def test_get_cipher_info_invalid_format(self):
        """Test get_cipher_info() handles invalid cipher format."""
        monitor = CertMonitor("www.example.com")

        # Return invalid format (not a 3-tuple)
        with patch.object(monitor, "_fetch_raw_cipher", return_value=("invalid",)):
            result = monitor.get_cipher_info()

            assert isinstance(result, dict)
            assert result["error"] == "CipherInfoError"
            assert "Unexpected cipher info format" in result["message"]
