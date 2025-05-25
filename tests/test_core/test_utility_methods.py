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
        """Test _to_structured_dict with invalid tuple length to cover exception handling."""
        monitor = CertMonitor("www.example.com")

        # Test with invalid tuple structure (not key-value pairs)
        data = [("single_value",)]  # Tuple with only one element

        result = monitor._to_structured_dict(data)
        # Should return a list when not all items are valid 2-tuples
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == ["single_value"]
