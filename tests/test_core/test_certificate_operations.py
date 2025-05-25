"""Tests for CertMonitor certificate operations functionality."""

from unittest.mock import MagicMock, patch

from certmonitor import CertMonitor


class TestCertificateRetrieval:
    """Test certificate information retrieval methods."""

    def test_get_cert_info_hostname(self, cert_monitor, sample_cert):
        """Test get_cert_info with hostname."""
        with patch.object(cert_monitor, "get_cert_info", return_value=sample_cert):
            result = cert_monitor.get_cert_info()
        assert result == sample_cert

    def test_get_cert_info_ip(self):
        """Test get_cert_info with IP address."""
        monitor = CertMonitor("192.168.1.1")
        sample_ip_cert = {"subject": {"commonName": "192.168.1.1"}}
        with patch.object(monitor, "get_cert_info", return_value=sample_ip_cert):
            result = monitor.get_cert_info()
        assert result == sample_ip_cert

    def test_get_cert_info_success(self):
        """Test get_cert_info() successful execution."""
        monitor = CertMonitor("www.example.com")
        monitor.cert_info = None

        mock_cert_data = {
            "cert_info": {"subject": {"commonName": "example.com"}},
            "der": b"mock_der",
            "pem": "mock_pem",
        }

        with patch.object(monitor, "_ensure_connection", return_value=None):
            with patch.object(monitor, "_fetch_raw_cert", return_value=mock_cert_data):
                result = monitor.get_cert_info()

                assert isinstance(result, dict)
                assert "subject" in result
                assert monitor.cert_info is not None

    def test_get_cert_info_already_cached(self):
        """Test get_cert_info() returns cached data when available."""
        monitor = CertMonitor("www.example.com")
        cached_cert_info = {"subject": {"commonName": "cached.example.com"}}
        monitor.cert_info = cached_cert_info

        result = monitor.get_cert_info()
        assert result == cached_cert_info

    def test_get_cert_info_connection_error(self):
        """Test get_cert_info() handles connection errors."""
        monitor = CertMonitor("www.example.com")
        monitor.cert_info = None

        connection_error = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(monitor, "_ensure_connection", return_value=connection_error):
            result = monitor.get_cert_info()
            assert result == connection_error

    def test_get_cert_info_exception_handling(self):
        """Test get_cert_info() handles unexpected exceptions."""
        monitor = CertMonitor("www.example.com")
        monitor.cert_info = None

        with patch.object(monitor, "_ensure_connection", return_value=None):
            with patch.object(
                monitor, "_fetch_raw_cert", side_effect=ValueError("Test error")
            ):
                result = monitor.get_cert_info()

                assert isinstance(result, dict)
                assert result["error"] == "UnknownError"
                assert "Test error" in result["message"]

    def test_graceful_error_handling_in_get_cert_info(self, cert_monitor, sample_cert):
        """Test that get_cert_info handles errors gracefully with new error handling."""
        # Mock _fetch_raw_cert to return an error
        error_response = {
            "error": "ConnectionError",
            "message": "Failed to connect",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(cert_monitor, "_fetch_raw_cert", return_value=error_response):
            result = cert_monitor.get_cert_info()

        # Should return the error response instead of raising an exception
        assert result == error_response
        assert isinstance(result, dict)
        assert "error" in result


class TestRawCertificateData:
    """Test raw certificate data retrieval methods."""

    def test_get_raw_der(self, cert_monitor):
        """Test get_raw_der method."""
        mock_der = b"mock der data"
        cert_monitor.der = mock_der
        cert_monitor.handler.fetch_raw_cert.return_value = {"der": mock_der}

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            assert cert_monitor.get_raw_der() == mock_der

    def test_get_raw_pem(self, cert_monitor):
        """Test get_raw_pem method."""
        mock_pem = (
            "-----BEGIN CERTIFICATE-----\nmock pem data\n-----END CERTIFICATE-----\n"
        )
        cert_monitor.pem = mock_pem
        cert_monitor.handler.fetch_raw_cert.return_value = {"pem": mock_pem}

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            assert cert_monitor.get_raw_pem() == mock_pem

    def test_get_raw_der_with_none_der(self, cert_monitor):
        """Test get_raw_der when der attribute is None and needs to fetch from handler."""
        mock_der = b"fetched der data"
        cert_monitor.der = None
        cert_monitor.handler.fetch_raw_cert.return_value = {"der": mock_der}

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            result = cert_monitor.get_raw_der()
            assert result == mock_der
            assert cert_monitor.der == mock_der

    def test_get_raw_pem_with_none_pem(self, cert_monitor):
        """Test get_raw_pem when pem attribute is None and needs to fetch from handler."""
        mock_pem = (
            "-----BEGIN CERTIFICATE-----\nfetched pem data\n-----END CERTIFICATE-----\n"
        )
        cert_monitor.pem = None
        cert_monitor.handler.fetch_raw_cert.return_value = {"pem": mock_pem}

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            result = cert_monitor.get_raw_pem()
            assert result == mock_pem
            assert cert_monitor.pem == mock_pem

    def test_get_raw_der_non_ssl_protocol_error(self):
        """Test get_raw_der returns protocol error for non-SSL protocols."""
        monitor = CertMonitor("www.example.com")
        monitor.protocol = "ssh"

        result = monitor.get_raw_der()

        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "ProtocolError"
        assert (
            "DER format is only available for SSL/TLS connections" in result["message"]
        )

    def test_get_raw_pem_non_ssl_protocol_error(self):
        """Test get_raw_pem returns protocol error for non-SSL protocols."""
        monitor = CertMonitor("www.example.com")
        monitor.protocol = "ssh"

        result = monitor.get_raw_pem()

        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "ProtocolError"
        assert (
            "PEM format is only available for SSL/TLS connections" in result["message"]
        )

    def test_get_raw_der_error_from_handler(self):
        """Test get_raw_der when handler returns an error to cover line 319."""
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
        """Test get_raw_pem when handler returns an error to cover line 341."""
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


class TestCertificateFetching:
    """Test certificate fetching and parsing operations."""

    def test_fetch_cert_error(self, cert_monitor):
        """Test fetch certificate error handling."""
        # Mock the handler to return an error dictionary instead of raising an exception
        cert_monitor.handler.fetch_raw_cert.return_value = {
            "error": "SocketError",
            "message": "Connection failed",
            "host": "www.example.com",
            "port": 443,
        }

        with patch.object(cert_monitor, "_ensure_connection", return_value=None):
            result = cert_monitor._fetch_raw_cert()

        # Verify that the error dictionary is returned
        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "SocketError"
        assert "Connection failed" in result["message"]

    def test_fetch_raw_cert_connection_error(self):
        """Test _fetch_raw_cert when _ensure_connection returns an error to cover line 150."""
        monitor = CertMonitor("example.com")

        # Mock _ensure_connection to return an error
        with patch.object(
            monitor, "_ensure_connection", return_value={"error": "Connection failed"}
        ):
            result = monitor._fetch_raw_cert()
            assert result == {"error": "Connection failed"}

    def test_fetch_raw_cert_empty_cert_info(self):
        """Test _fetch_raw_cert when cert_info is empty to cover line 164."""
        monitor = CertMonitor("example.com")

        # Mock _ensure_connection to return None (success)
        with patch.object(monitor, "_ensure_connection", return_value=None):
            # Mock handler.fetch_raw_cert to return empty cert_info
            monitor.handler = MagicMock()
            monitor.handler.fetch_raw_cert.return_value = {
                "cert_info": {},  # Empty cert_info
                "pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
                "der": b"mock_der_data",
            }
            monitor.pem = "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"

            # Mock _parse_pem_cert
            with patch.object(
                monitor, "_parse_pem_cert", return_value={"parsed": "data"}
            ):
                result = monitor._fetch_raw_cert()
                # This should trigger the empty cert_info condition on line 164
                monitor._parse_pem_cert.assert_called_once()

    def test_parse_pem_cert(self):
        """Test _parse_pem_cert() method."""
        monitor = CertMonitor("www.example.com")
        mock_pem = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

        expected_cert_details = {
            "subject": {"commonName": "example.com"},
            "issuer": {"organizationName": "Test CA"},
        }

        with patch("ssl._ssl._test_decode_cert", return_value=expected_cert_details):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/test.pem"
                mock_temp.return_value.__enter__.return_value = mock_file
                with patch("os.remove") as mock_remove:
                    result = monitor._parse_pem_cert(mock_pem)
                    assert result == expected_cert_details
                    mock_remove.assert_called_once_with("/tmp/test.pem")


class TestDataTransformation:
    """Test data transformation and utility methods."""

    def test_to_structured_dict_simple_data(self):
        """Test _to_structured_dict() with simple data types."""
        monitor = CertMonitor("www.example.com")

        # Test with string
        assert monitor._to_structured_dict("test") == "test"

        # Test with int
        assert monitor._to_structured_dict(123) == 123

        # Test with None
        assert monitor._to_structured_dict(None) is None

    def test_to_structured_dict_tuple_list(self):
        """Test _to_structured_dict() with tuple list (certificate format)."""
        monitor = CertMonitor("www.example.com")

        data = [
            ("countryName", "US"),
            ("stateOrProvinceName", "CA"),
            ("organizationName", "Test Org"),
        ]

        result = monitor._to_structured_dict(data)
        expected = {
            "countryName": "US",
            "stateOrProvinceName": "CA",
            "organizationName": "Test Org",
        }

        assert result == expected

    def test_to_structured_dict_duplicate_keys(self):
        """Test _to_structured_dict() handles duplicate keys by creating lists."""
        monitor = CertMonitor("www.example.com")

        data = [
            ("organizationName", "Test Org 1"),
            ("organizationName", "Test Org 2"),
            ("countryName", "US"),
        ]

        result = monitor._to_structured_dict(data)

        assert isinstance(result["organizationName"], list)
        assert len(result["organizationName"]) == 2
        assert result["countryName"] == "US"

    def test_to_structured_dict_subject_issuer(self):
        """Test _to_structured_dict() special handling for subject/issuer."""
        monitor = CertMonitor("www.example.com")

        data = {
            "subject": [[("countryName", "US"), ("organizationName", "Test")]],
            "issuer": [[("countryName", "US"), ("organizationName", "CA")]],
            "version": 3,
        }

        result = monitor._to_structured_dict(data)

        assert result["subject"]["countryName"] == "US"
        assert result["subject"]["organizationName"] == "Test"
        assert result["issuer"]["countryName"] == "US"
        assert result["issuer"]["organizationName"] == "CA"
        assert result["version"] == 3

    def test_to_structured_dict_invalid_tuple_length(self):
        """Test _to_structured_dict with invalid tuple length to cover exception handling."""
        monitor = CertMonitor("www.example.com")

        # Test with invalid tuple structure (not key-value pairs)
        data = [("single_value",)]  # Tuple with only one element

        result = monitor._to_structured_dict(data)
        # Should return a list when not all items are valid 2-tuples
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == ["single_value"]
