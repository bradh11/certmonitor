# tests/test_core.py

from unittest.mock import MagicMock, patch

from certmonitor import CertMonitor


def test_validate(cert_monitor, sample_cert):
    cert_monitor.cert_info = sample_cert  # Not wrapped
    cert_monitor.cert_data = {"cert_info": sample_cert}  # Needed for validate()
    mock_validator = MagicMock(name="mock_validator")
    mock_validator.name = "mock_validator"
    mock_validator.validator_type = "cert"
    mock_validator.validate.return_value = {"is_valid": True}
    with patch.object(cert_monitor, "validators", {"mock_validator": mock_validator}):
        cert_monitor.enabled_validators = ["mock_validator"]
        result = cert_monitor.validate()
    assert "mock_validator" in result


def test_validate_with_args(cert_monitor, sample_cert):
    cert_monitor.cert_info = sample_cert  # Not wrapped
    cert_monitor.cert_data = {"cert_info": sample_cert}  # Needed for validate()
    mock_validator = MagicMock(name="subject_alt_names")
    mock_validator.name = "subject_alt_names"
    mock_validator.validator_type = "cert"
    mock_validator.validate.return_value = {"is_valid": True}
    with patch.object(
        cert_monitor, "validators", {"subject_alt_names": mock_validator}
    ):
        cert_monitor.enabled_validators = ["subject_alt_names"]
        result = cert_monitor.validate(
            validator_args={"subject_alt_names": ["example.com"]}
        )
    assert "subject_alt_names" in result
    mock_validator.validate.assert_called_once_with(
        {"cert_info": sample_cert},
        cert_monitor.host,
        cert_monitor.port,
        ["example.com"],
    )


def test_get_public_key_der_success(cert_monitor):
    """Test successful retrieval of public key in DER format."""
    mock_der = b"mock der data"
    mock_public_key_der = b"mock public key der data"
    cert_monitor.public_key_der = mock_public_key_der
    cert_monitor.handler.fetch_raw_cert.return_value = {
        "der": mock_der,
        "public_key_der": mock_public_key_der,
    }

    with patch.object(cert_monitor, "_ensure_connection", return_value=None):
        result = cert_monitor.get_public_key_der()
        assert result == mock_public_key_der


def test_get_public_key_der_protocol_error(cert_monitor):
    """Test get_public_key_der returns error for non-SSL protocols."""
    cert_monitor.protocol = "ssh"

    result = cert_monitor.get_public_key_der()

    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "ProtocolError"
    assert (
        "Public key extraction is only available for SSL/TLS connections"
        in result["message"]
    )


def test_get_public_key_der_connection_error(cert_monitor):
    """Test get_public_key_der handles connection errors."""
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


def test_get_public_key_der_fetch_error(cert_monitor):
    """Test get_public_key_der handles certificate fetch errors."""
    cert_monitor.public_key_der = None
    fetch_error = {
        "error": "CertificateError",
        "message": "Failed to fetch certificate",
        "host": "www.example.com",
        "port": 443,
    }

    with patch.object(cert_monitor, "_ensure_connection", return_value=None):
        with patch.object(cert_monitor, "_fetch_raw_cert", return_value=fetch_error):
            result = cert_monitor.get_public_key_der()
            assert result == fetch_error


def test_get_public_key_pem_success(cert_monitor):
    """Test successful retrieval of public key in PEM format."""
    mock_pem = "-----BEGIN CERTIFICATE-----\nmock pem data\n-----END CERTIFICATE-----\n"
    mock_public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\nmock public key pem data\n-----END PUBLIC KEY-----"
    )
    cert_monitor.public_key_pem = mock_public_key_pem
    cert_monitor.handler.fetch_raw_cert.return_value = {
        "pem": mock_pem,
        "public_key_pem": mock_public_key_pem,
    }

    with patch.object(cert_monitor, "_ensure_connection", return_value=None):
        result = cert_monitor.get_public_key_pem()
        assert result == mock_public_key_pem


def test_get_public_key_pem_protocol_error(cert_monitor):
    """Test get_public_key_pem returns error for non-SSL protocols."""
    cert_monitor.protocol = "ssh"

    result = cert_monitor.get_public_key_pem()

    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "ProtocolError"
    assert (
        "Public key extraction is only available for SSL/TLS connections"
        in result["message"]
    )


def test_get_public_key_pem_connection_error(cert_monitor):
    """Test get_public_key_pem handles connection errors."""
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


def test_get_public_key_pem_fetch_error(cert_monitor):
    """Test get_public_key_pem handles certificate fetch errors."""
    cert_monitor.public_key_pem = None
    fetch_error = {
        "error": "CertificateError",
        "message": "Failed to fetch certificate",
        "host": "www.example.com",
        "port": 443,
    }

    with patch.object(cert_monitor, "_ensure_connection", return_value=None):
        with patch.object(cert_monitor, "_fetch_raw_cert", return_value=fetch_error):
            result = cert_monitor.get_public_key_pem()
            assert result == fetch_error


def test_graceful_error_handling_in_get_cert_info(cert_monitor, sample_cert):
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


def test_get_raw_der_with_none_der(cert_monitor):
    """Test get_raw_der when der attribute is None and needs to fetch from handler."""
    mock_der = b"fetched der data"
    cert_monitor.der = None
    cert_monitor.handler.fetch_raw_cert.return_value = {"der": mock_der}

    with patch.object(cert_monitor, "_ensure_connection", return_value=None):
        result = cert_monitor.get_raw_der()
        assert result == mock_der
        assert cert_monitor.der == mock_der


def test_get_raw_pem_with_none_pem(cert_monitor):
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


def test_get_raw_der_non_ssl_protocol_error():
    """Test get_raw_der returns protocol error for non-SSL protocols."""
    monitor = CertMonitor("www.example.com")
    monitor.protocol = "ssh"

    result = monitor.get_raw_der()

    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "ProtocolError"
    assert "DER format is only available for SSL/TLS connections" in result["message"]


def test_get_raw_pem_non_ssl_protocol_error():
    """Test get_raw_pem returns protocol error for non-SSL protocols."""
    monitor = CertMonitor("www.example.com")
    monitor.protocol = "ssh"

    result = monitor.get_raw_pem()

    assert isinstance(result, dict)
    assert "error" in result
    assert result["error"] == "ProtocolError"
    assert "PEM format is only available for SSL/TLS connections" in result["message"]


def test_cert_data_contains_public_key_info_after_fetch(cert_monitor):
    """Test that cert_data contains public key information after successful fetch."""
    mock_der = b"mock der data"
    mock_pem = "-----BEGIN CERTIFICATE-----\nmock pem data\n-----END CERTIFICATE-----\n"
    mock_cert_info = {"subject": {"commonName": "example.com"}}
    mock_public_key_der = b"mock public key der"
    mock_public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\nmock key\n-----END PUBLIC KEY-----"
    )
    mock_public_key_info = {"algorithm": "rsaEncryption", "size": 2048, "curve": None}

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


def test_public_key_methods_return_none_when_not_available(cert_monitor):
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


def test_error_handling_integration(cert_monitor):
    """Integration test for error handling across multiple methods."""
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
        # All methods should return the same error
        assert cert_monitor.get_raw_der() == connection_error
        assert cert_monitor.get_raw_pem() == connection_error
        assert cert_monitor.get_public_key_der() == connection_error
        assert cert_monitor.get_public_key_pem() == connection_error


# Additional comprehensive tests for better coverage


def test_parse_pem_cert():
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


def test_to_structured_dict_simple_data():
    """Test _to_structured_dict() with simple data types."""
    monitor = CertMonitor("www.example.com")

    # Test with string
    assert monitor._to_structured_dict("test") == "test"

    # Test with int
    assert monitor._to_structured_dict(123) == 123

    # Test with None
    assert monitor._to_structured_dict(None) is None


def test_to_structured_dict_tuple_list():
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


def test_to_structured_dict_duplicate_keys():
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


def test_to_structured_dict_subject_issuer():
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


def test_get_cert_info_success():
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


def test_get_cert_info_already_cached():
    """Test get_cert_info() returns cached data when available."""
    monitor = CertMonitor("www.example.com")
    cached_cert_info = {"subject": {"commonName": "cached.example.com"}}
    monitor.cert_info = cached_cert_info

    result = monitor.get_cert_info()
    assert result == cached_cert_info


def test_get_cert_info_connection_error():
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


def test_get_cert_info_exception_handling():
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


def test_fetch_raw_cipher_success():
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


def test_fetch_raw_cipher_non_ssl_protocol():
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


def test_fetch_raw_cipher_connection_error():
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


def test_get_cipher_info_success():
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


def test_get_cipher_info_tls13_special_handling():
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
            assert "Not applicable" in result["cipher_suite"]["key_exchange_algorithm"]


def test_get_cipher_info_error_response():
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


def test_get_cipher_info_invalid_format():
    """Test get_cipher_info() handles invalid cipher format."""
    monitor = CertMonitor("www.example.com")

    # Return invalid format (not a 3-tuple)
    with patch.object(monitor, "_fetch_raw_cipher", return_value=("invalid",)):
        result = monitor.get_cipher_info()

        assert isinstance(result, dict)
        assert result["error"] == "CipherInfoError"
        assert "Unexpected cipher info format" in result["message"]


def test_validate_unknown_validators():
    """Test validate() handles unknown validators."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["unknown_validator", "another_unknown"]

    result = monitor.validate()

    assert "unknown_validator" in result
    assert "another_unknown" in result
    assert result["unknown_validator"]["is_valid"] is False
    assert "not implemented" in result["unknown_validator"]["reason"]


def test_validate_cert_validators_no_cert_data():
    """Test validate() handles missing cert data for cert validators."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["hostname"]

    # Mock a cert validator
    mock_validator = MagicMock()
    mock_validator.name = "hostname"
    mock_validator.validator_type = "cert"

    with patch.object(monitor, "validators", {"hostname": mock_validator}):
        # No cert_data attribute
        result = monitor.validate()

        assert "hostname" in result
        assert result["hostname"]["is_valid"] is False
        assert "Certificate data is missing" in result["hostname"]["reason"]


def test_validate_cert_validators_cert_data_error():
    """Test validate() handles cert data with errors."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["hostname"]
    monitor.cert_data = {
        "error": "CertificateError",
        "message": "Failed to fetch certificate",
    }

    # Mock a cert validator
    mock_validator = MagicMock()
    mock_validator.name = "hostname"
    mock_validator.validator_type = "cert"

    with patch.object(monitor, "validators", {"hostname": mock_validator}):
        result = monitor.validate()

        assert "hostname" in result
        assert result["hostname"]["is_valid"] is False
        assert "CertificateError" in result["hostname"]["reason"]


def test_validate_cert_validators_success():
    """Test validate() successful cert validator execution."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["hostname"]
    monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

    # Mock a cert validator
    mock_validator = MagicMock()
    mock_validator.name = "hostname"
    mock_validator.validator_type = "cert"
    mock_validator.validate.return_value = {
        "is_valid": True,
        "reason": "Hostname matches",
    }

    with patch.object(monitor, "validators", {"hostname": mock_validator}):
        result = monitor.validate()

        assert "hostname" in result
        assert result["hostname"]["is_valid"] is True
        mock_validator.validate.assert_called_once_with(
            monitor.cert_data, monitor.host, monitor.port
        )


def test_validate_cert_validators_with_subject_alt_names_args():
    """Test validate() with subject_alt_names validator arguments."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["subject_alt_names"]
    monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

    # Mock subject_alt_names validator
    mock_validator = MagicMock()
    mock_validator.name = "subject_alt_names"
    mock_validator.validator_type = "cert"
    mock_validator.validate.return_value = {"is_valid": True}

    with patch.object(monitor, "validators", {"subject_alt_names": mock_validator}):
        validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
        result = monitor.validate(validator_args=validator_args)

        assert "subject_alt_names" in result
        mock_validator.validate.assert_called_once_with(
            monitor.cert_data,
            monitor.host,
            monitor.port,
            ["example.com", "www.example.com"],
        )


def test_validate_cert_validators_with_other_args():
    """Test validate() with other validator arguments (non-subject_alt_names)."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["custom_validator"]
    monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

    # Mock custom validator
    mock_validator = MagicMock()
    mock_validator.name = "custom_validator"
    mock_validator.validator_type = "cert"
    mock_validator.validate.return_value = {"is_valid": True}

    with patch.object(monitor, "validators", {"custom_validator": mock_validator}):
        validator_args = {"custom_validator": ["arg1", "arg2"]}
        result = monitor.validate(validator_args=validator_args)

        assert "custom_validator" in result
        mock_validator.validate.assert_called_once_with(
            monitor.cert_data, monitor.host, monitor.port, "arg1", "arg2"
        )


def test_validate_cipher_validators_success():
    """Test validate() successful cipher validator execution."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["weak_cipher"]

    # Mock cipher validator
    mock_validator = MagicMock()
    mock_validator.name = "weak_cipher"
    mock_validator.validator_type = "cipher"
    mock_validator.validate.return_value = {"is_valid": True, "reason": "Strong cipher"}

    mock_cipher_info = {
        "cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256"},
        "protocol_version": "TLSv1.2",
    }

    with patch.object(monitor, "validators", {"weak_cipher": mock_validator}):
        with patch.object(monitor, "get_cipher_info", return_value=mock_cipher_info):
            result = monitor.validate()

            assert "weak_cipher" in result
            assert result["weak_cipher"]["is_valid"] is True
            mock_validator.validate.assert_called_once_with(
                mock_cipher_info, monitor.host, monitor.port
            )


def test_validate_cipher_validators_cipher_error():
    """Test validate() handles cipher info errors for cipher validators."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["weak_cipher"]

    # Mock cipher validator
    mock_validator = MagicMock()
    mock_validator.name = "weak_cipher"
    mock_validator.validator_type = "cipher"

    cipher_error = {
        "error": "ConnectionError",
        "message": "Failed to get cipher info",
    }

    with patch.object(monitor, "validators", {"weak_cipher": mock_validator}):
        with patch.object(monitor, "get_cipher_info", return_value=cipher_error):
            result = monitor.validate()

            # Cipher validators should be skipped when cipher info has errors
            assert "weak_cipher" not in result or len(result) == 0


def test_validate_cipher_validators_with_args():
    """Test validate() cipher validators with additional arguments."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["custom_cipher_validator"]

    # Mock cipher validator
    mock_validator = MagicMock()
    mock_validator.name = "custom_cipher_validator"
    mock_validator.validator_type = "cipher"
    mock_validator.validate.return_value = {"is_valid": True}

    mock_cipher_info = {"cipher_suite": {"name": "test"}}

    with patch.object(
        monitor, "validators", {"custom_cipher_validator": mock_validator}
    ):
        with patch.object(monitor, "get_cipher_info", return_value=mock_cipher_info):
            validator_args = {"custom_cipher_validator": ["arg1", "arg2"]}
            result = monitor.validate(validator_args=validator_args)

            assert "custom_cipher_validator" in result
            mock_validator.validate.assert_called_once_with(
                mock_cipher_info, monitor.host, monitor.port, "arg1", "arg2"
            )


def test_validate_mixed_validators():
    """Test validate() with both cert and cipher validators."""
    monitor = CertMonitor("www.example.com")
    monitor.enabled_validators = ["hostname", "weak_cipher"]
    monitor.cert_data = {"cert_info": {"subject": {"commonName": "example.com"}}}

    # Mock cert validator
    mock_cert_validator = MagicMock()
    mock_cert_validator.name = "hostname"
    mock_cert_validator.validator_type = "cert"
    mock_cert_validator.validate.return_value = {"is_valid": True}

    # Mock cipher validator
    mock_cipher_validator = MagicMock()
    mock_cipher_validator.name = "weak_cipher"
    mock_cipher_validator.validator_type = "cipher"
    mock_cipher_validator.validate.return_value = {"is_valid": True}

    mock_cipher_info = {"cipher_suite": {"name": "test"}}

    validators = {"hostname": mock_cert_validator, "weak_cipher": mock_cipher_validator}

    with patch.object(monitor, "validators", validators):
        with patch.object(monitor, "get_cipher_info", return_value=mock_cipher_info):
            result = monitor.validate()

            assert "hostname" in result
            assert "weak_cipher" in result
            assert result["hostname"]["is_valid"] is True
            assert result["weak_cipher"]["is_valid"] is True


def test_initialization_with_default_validators():
    """Test initialization uses default validators when empty list provided."""
    with patch("certmonitor.core.config.ENABLED_VALIDATORS", ["default1", "default2"]):
        monitor = CertMonitor("www.example.com", enabled_validators=[])
        # The implementation uses: enabled_validators or config.ENABLED_VALIDATORS
        assert monitor.enabled_validators == ["default1", "default2"]


def test_initialization_with_empty_list():
    """Test initialization with empty validator list."""
    monitor = CertMonitor("www.example.com", enabled_validators=[])
    assert monitor.enabled_validators == []


def test_fetch_raw_cert_connection_error():
    """Test _fetch_raw_cert when _ensure_connection returns an error to cover line 150."""
    monitor = CertMonitor("example.com")

    # Mock _ensure_connection to return an error
    with patch.object(
        monitor, "_ensure_connection", return_value={"error": "Connection failed"}
    ):
        result = monitor._fetch_raw_cert()
        assert result == {"error": "Connection failed"}


def test_fetch_raw_cert_empty_cert_info():
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
        with patch.object(monitor, "_parse_pem_cert", return_value={"parsed": "data"}):
            result = monitor._fetch_raw_cert()
            # This should trigger the empty cert_info condition on line 164
            monitor._parse_pem_cert.assert_called_once()


def test_get_raw_der_error_from_handler():
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


def test_get_raw_pem_error_from_handler():
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


def test_to_structured_dict_invalid_tuple_length():
    """Test _to_structured_dict with invalid tuple length to cover exception handling."""
    monitor = CertMonitor("www.example.com")

    # Test with invalid tuple structure (not key-value pairs)
    data = [("single_value",)]  # Tuple with only one element

    result = monitor._to_structured_dict(data)
    # Should return a list when not all items are valid 2-tuples
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0] == ["single_value"]
