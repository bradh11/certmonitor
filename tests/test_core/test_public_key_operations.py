"""Tests for CertMonitor public key operations and extraction methods."""

import pytest
from unittest.mock import patch, MagicMock
from certmonitor.core import CertMonitor


class TestPublicKeyExtraction:
    """Test public key extraction methods (DER and PEM formats)."""

    def test_get_public_key_der_success(self, cert_monitor):
        """Test successful get_public_key_der operation."""
        mock_der = b"mock public key der data"
        cert_monitor.public_key_der = mock_der

        result = cert_monitor.get_public_key_der()
        assert result == mock_der

    def test_get_public_key_der_protocol_error(self, cert_monitor):
        """Test get_public_key_der with protocol error."""
        protocol_error = {
            "error": "ProtocolError",
            "message": "Public keys are only available for SSL/TLS connections",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(
            cert_monitor, "_ensure_connection", return_value=protocol_error
        ):
            result = cert_monitor.get_public_key_der()
            assert result == protocol_error

    def test_get_public_key_der_connection_error(self, cert_monitor):
        """Test get_public_key_der with connection error."""
        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(
            cert_monitor, "_ensure_connection", return_value=connection_error
        ):
            result = cert_monitor.get_public_key_der()
            assert result == connection_error

    def test_get_public_key_der_fetch_error(self, cert_monitor):
        """Test get_public_key_der with fetch error."""
        fetch_error = {
            "error": "FetchError",
            "message": "Failed to fetch certificate data",
            "host": "www.example.com",
            "port": 443,
        }

        cert_monitor.public_key_der = None
        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            with patch.object(
                cert_monitor, "_fetch_raw_cert", return_value=fetch_error
            ):
                result = cert_monitor.get_public_key_der()
                assert result == fetch_error

    def test_get_public_key_pem_success(self, cert_monitor):
        """Test successful get_public_key_pem operation."""
        mock_pem = "-----BEGIN PUBLIC KEY-----\nmock key data\n-----END PUBLIC KEY-----"
        cert_monitor.public_key_pem = mock_pem

        result = cert_monitor.get_public_key_pem()
        assert result == mock_pem

    def test_get_public_key_pem_protocol_error(self, cert_monitor):
        """Test get_public_key_pem with protocol error."""
        protocol_error = {
            "error": "ProtocolError",
            "message": "Public keys are only available for SSL/TLS connections",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(
            cert_monitor, "_ensure_connection", return_value=protocol_error
        ):
            result = cert_monitor.get_public_key_pem()
            assert result == protocol_error

    def test_get_public_key_pem_connection_error(self, cert_monitor):
        """Test get_public_key_pem with connection error."""
        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(
            cert_monitor, "_ensure_connection", return_value=connection_error
        ):
            result = cert_monitor.get_public_key_pem()
            assert result == connection_error

    def test_get_public_key_pem_fetch_error(self, cert_monitor):
        """Test get_public_key_pem with fetch error."""
        fetch_error = {
            "error": "FetchError",
            "message": "Failed to fetch certificate data",
            "host": "www.example.com",
            "port": 443,
        }

        cert_monitor.public_key_pem = None
        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            with patch.object(
                cert_monitor, "_fetch_raw_cert", return_value=fetch_error
            ):
                result = cert_monitor.get_public_key_pem()
                assert result == fetch_error


class TestPublicKeyDataIntegration:
    """Test public key data integration and storage."""

    def test_cert_data_contains_public_key_info_after_fetch(self, cert_monitor):
        """Test that cert_data contains public key information after successful fetch."""
        mock_der = b"mock der data"
        mock_pem = (
            "-----BEGIN CERTIFICATE-----\nmock pem data\n-----END CERTIFICATE-----\n"
        )
        mock_cert_info = {"subject": {"commonName": "example.com"}}
        mock_public_key_der = b"mock public key der"
        mock_public_key_pem = (
            "-----BEGIN PUBLIC KEY-----\nmock key\n-----END PUBLIC KEY-----"
        )
        mock_public_key_info = {
            "algorithm": "rsaEncryption",
            "size": 2048,
            "curve": None,
        }

        # Mock the handler's fetch_raw_cert to return basic cert data
        cert_monitor.handler.fetch_raw_cert.return_value = {
            "cert_info": mock_cert_info,
            "der": mock_der,
            "pem": mock_pem,
        }

        # Mock the certinfo functions
        with patch("certmonitor.core.certinfo") as mock_certinfo:
            mock_certinfo.parse_public_key_info.return_value = mock_public_key_info
            mock_certinfo.extract_public_key_der.return_value = mock_public_key_der
            mock_certinfo.extract_public_key_pem.return_value = mock_public_key_pem

            with patch.object(cert_monitor, "_ensure_connection", return_value=None):
                cert_monitor._fetch_raw_cert()

        # Verify cert_data contains all the expected public key information
        assert hasattr(cert_monitor, "cert_data")
        assert isinstance(cert_monitor.cert_data, dict)
        assert "public_key_info" in cert_monitor.cert_data
        assert "public_key_der" in cert_monitor.cert_data
        assert "public_key_pem" in cert_monitor.cert_data
        assert cert_monitor.cert_data["public_key_info"] == mock_public_key_info
        assert cert_monitor.cert_data["public_key_der"] == mock_public_key_der
        assert cert_monitor.cert_data["public_key_pem"] == mock_public_key_pem

    def test_public_key_methods_return_none_when_not_available(self, cert_monitor):
        """Test that public key methods return None when public keys are not available."""
        # Mock _fetch_raw_cert to return cert data without public keys (DER not available case)
        cert_monitor.public_key_der = None
        cert_monitor.public_key_pem = None

        def mock_fetch_raw_cert():
            cert_monitor.public_key_der = None
            cert_monitor.public_key_pem = None
            return {
                "public_key_info": {"error": "DER bytes not available"},
                "public_key_der": None,
                "public_key_pem": None,
            }

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            with patch.object(
                cert_monitor, "_fetch_raw_cert", side_effect=mock_fetch_raw_cert
            ):
                der_result = cert_monitor.get_public_key_der()
                pem_result = cert_monitor.get_public_key_pem()

                assert der_result is None
                assert pem_result is None


class TestPublicKeyErrorHandling:
    """Test error handling for public key operations."""

    def test_error_handling_integration(self, cert_monitor):
        """Integration test for error handling across multiple public key methods."""
        # Test that errors are handled consistently across different methods
        connection_error = {
            "error": "ConnectionError",
            "message": "Network unreachable",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(
            cert_monitor, "_ensure_connection", return_value=connection_error
        ):
            # All public key methods should return the same error
            assert cert_monitor.get_public_key_der() == connection_error
            assert cert_monitor.get_public_key_pem() == connection_error
