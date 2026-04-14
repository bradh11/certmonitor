"""Tests for CertMonitor utility methods and data transformation."""

from certmonitor.core import CertMonitor


class TestStructuredDictConversion:
    """Test _to_structured_dict() utility method for data transformation."""

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
        """Test _to_structured_dict handles invalid tuple structures gracefully."""
        monitor = CertMonitor("www.example.com")

        # Test with invalid tuple structure (not key-value pairs)
        data = [("single_value",)]  # Tuple with only one element

        result = monitor._to_structured_dict(data)
        # Should return a list when not all items are valid 2-tuples
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == ["single_value"]


class TestDescribeValidators:
    """Test CertMonitor.describe_validators() introspection helper."""

    def test_describe_validators_returns_all_registered(self):
        """Every registered validator appears in the description."""
        monitor = CertMonitor("www.example.com")
        described = monitor.describe_validators()
        assert set(described.keys()) >= {
            "expiration",
            "hostname",
            "key_info",
            "subject_alt_names",
            "root_certificate",
            "sensitive_date",
            "tls_version",
            "weak_cipher",
        }

    def test_describe_validators_subject_alt_names_args(self):
        """subject_alt_names exposes ``alternate_names`` with annotation and default."""
        monitor = CertMonitor("www.example.com")
        described = monitor.describe_validators()

        san = described["subject_alt_names"]
        assert san["validator_type"] == "cert"
        assert "alternate_names" in san["args"]
        arg = san["args"]["alternate_names"]
        assert arg["default"] is None
        assert arg["required"] is False
        assert "List" in arg["annotation"] and "str" in arg["annotation"]

    def test_describe_validators_validator_with_no_args(self):
        """Validators without user args report an empty args dict."""
        monitor = CertMonitor("www.example.com")
        described = monitor.describe_validators()

        assert described["expiration"]["args"] == {}
        assert described["hostname"]["args"] == {}

    def test_describe_validators_includes_doc(self):
        """Each entry includes the first line of the validator's class docstring."""
        monitor = CertMonitor("www.example.com")
        described = monitor.describe_validators()
        assert described["subject_alt_names"]["doc"]
        assert isinstance(described["subject_alt_names"]["doc"], str)

    def test_describe_validators_renders_plain_class_annotations(self):
        """Plain-class annotations like ``int`` render without ``<class 'int'>``."""
        from certmonitor.validators.base import BaseCertValidator

        class PlainAnnotationValidator(BaseCertValidator):
            @property
            def name(self):
                return "plain_annotation"

            def validate(self, cert_info, host, port, *, threshold: int = 0):
                return {"is_valid": True}

        monitor = CertMonitor("www.example.com")
        monitor.validators = {"plain_annotation": PlainAnnotationValidator()}
        described = monitor.describe_validators()
        assert described["plain_annotation"]["args"]["threshold"]["annotation"] == "int"
        assert described["plain_annotation"]["args"]["threshold"]["default"] == 0
