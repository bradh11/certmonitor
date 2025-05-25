# tests/test_validators/test_hostname.py

from certmonitor.validators.hostname import HostnameValidator


class TestHostnameValidator:
    """Test suite for HostnameValidator."""

    def test_validator_name(self):
        """Test validator name property."""
        validator = HostnameValidator()
        assert validator.name == "hostname"

    def test_hostname_matches_san_dns(self, sample_cert):
        """Test hostname validation when hostname matches SAN DNS names."""
        validator = HostnameValidator()
        result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert "matched_name" in result
        assert "alt_names" in result

    def test_hostname_mismatch(self, sample_cert):
        """Test hostname validation when hostname doesn't match."""
        validator = HostnameValidator()
        result = validator.validate({"cert_info": sample_cert}, "invalid.com", 443)
        assert result["is_valid"] is False
        assert "reason" in result
        assert "invalid.com" in result["reason"]
        assert "alt_names" in result

    def test_hostname_matches_common_name(self):
        """Test hostname validation when hostname matches common name."""
        cert_info = {
            "subject": {"commonName": "example.com"},
            # No subjectAltName to force common name check
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "example.com"
        assert result["alt_names"] == []

    def test_hostname_no_san_extension(self):
        """Test hostname validation when certificate has no SAN extension."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            # No subjectAltName extension
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is False
        assert "Subject Alternative Name extension" in result["reason"]

    def test_hostname_san_dict_format_single_dns(self):
        """Test SAN in dict format with single DNS name."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": "example.com"},
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "example.com"
        assert "example.com" in result["alt_names"]

    def test_hostname_san_dict_format_multiple_dns(self):
        """Test SAN in dict format with multiple DNS names."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": ["example.com", "www.example.com"]},
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "www.example.com"
        assert "www.example.com" in result["alt_names"]

    def test_hostname_san_list_format(self):
        """Test SAN in list format."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "example.com"
        assert "example.com" in result["alt_names"]

    def test_hostname_no_dns_sans(self):
        """Test when SAN exists but contains no DNS names."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"IP": "192.168.1.1"},  # No DNS entries
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is False
        assert "does not contain any DNS SANs" in result["reason"]
        assert result["alt_names"] == []

    def test_hostname_wildcard_match(self):
        """Test wildcard certificate matching."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": ["*.example.com"]},
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "*.example.com"
        assert "*.example.com" in result["alt_names"]

    def test_hostname_wildcard_no_match_wrong_level(self):
        """Test wildcard that doesn't match due to wrong subdomain level."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": ["*.example.com"]},
        }
        validator = HostnameValidator()
        # Too many levels - should not match *.example.com
        result = validator.validate(
            {"cert_info": cert_info}, "sub.www.example.com", 443
        )
        assert result["is_valid"] is False
        assert "doesn't match any of the certificate's" in result["reason"]

    def test_hostname_wildcard_no_match_different_domain(self):
        """Test wildcard that doesn't match due to different domain."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": ["*.example.com"]},
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "www.other.com", 443)
        assert result["is_valid"] is False
        assert "doesn't match any of the certificate's" in result["reason"]

    def test_hostname_case_insensitive_matching(self):
        """Test case insensitive hostname matching."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": {"DNS": ["EXAMPLE.COM"]},
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True

    def test_common_name_fallback_when_no_subject(self):
        """Test common name extraction when subject is missing."""
        cert_info = {}  # No subject field
        validator = HostnameValidator()
        common_name = validator._get_common_name(cert_info)
        assert common_name is None

    def test_common_name_fallback_when_no_common_name(self):
        """Test common name extraction when commonName is missing."""
        cert_info = {"subject": {}}  # Subject exists but no commonName
        validator = HostnameValidator()
        common_name = validator._get_common_name(cert_info)
        assert common_name is None

    def test_matches_hostname_case_insensitive(self):
        """Test _matches_hostname method for case insensitive matching."""
        validator = HostnameValidator()
        assert validator._matches_hostname("Example.COM", ["example.com"]) is True
        assert validator._matches_hostname("example.com", ["EXAMPLE.COM"]) is True
        assert validator._matches_hostname("different.com", ["example.com"]) is False

    def test_matches_wildcard_valid_pattern(self):
        """Test _matches_wildcard method with valid wildcard patterns."""
        validator = HostnameValidator()
        assert validator._matches_wildcard("www.example.com", "*.example.com") is True
        assert validator._matches_wildcard("sub.test.com", "*.test.com") is True

    def test_matches_wildcard_invalid_pattern(self):
        """Test _matches_wildcard method with invalid patterns."""
        validator = HostnameValidator()
        # Pattern doesn't start with *.
        assert validator._matches_wildcard("www.example.com", "example.com") is False
        # Wrong number of parts
        assert (
            validator._matches_wildcard("sub.www.example.com", "*.example.com") is False
        )
        # Different domain
        assert validator._matches_wildcard("www.other.com", "*.example.com") is False

    def test_san_list_format_mixed_types(self):
        """Test SAN in list format with mixed entry types."""
        cert_info = {
            "subject": {"commonName": "different.com"},
            "subjectAltName": [
                ("DNS", "example.com"),
                ("IP Address", "192.168.1.1"),
                ("DNS", "www.example.com"),
            ],
        }
        validator = HostnameValidator()
        result = validator.validate({"cert_info": cert_info}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert result["matched_name"] == "www.example.com"
        # Should only include DNS names
        assert "example.com" in result["alt_names"]
        assert "www.example.com" in result["alt_names"]
