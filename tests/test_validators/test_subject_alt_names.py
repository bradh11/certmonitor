# tests/test_validators/test_subject_alt_names.py

from certmonitor.validators.subject_alt_names import SubjectAltNamesValidator


class TestSubjectAltNamesValidator:
    """Test suite for SubjectAltNamesValidator."""

    def test_validator_name(self):
        """Test validator name property."""
        validator = SubjectAltNamesValidator()
        assert validator.name == "subject_alt_names"

    def test_san_validation_success_with_alternates(self, sample_cert):
        """Test SAN validation success with alternate names."""
        validator = SubjectAltNamesValidator()
        result = validator.validate(
            {"cert_info": sample_cert}, "www.example.com", 443, ["example.com"]
        )
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert result["contains_alternate"]["example.com"]["is_valid"] is True
        assert result["count"] > 0

    def test_san_validation_partial_mismatch(self, sample_cert):
        """Test SAN validation with partial mismatch."""
        validator = SubjectAltNamesValidator()
        result = validator.validate(
            {"cert_info": sample_cert}, "www.example.com", 443, ["invalid.com"]
        )
        assert result["is_valid"] is True  # Host is valid
        assert result["contains_host"]["is_valid"] is True
        assert result["contains_alternate"]["invalid.com"]["is_valid"] is False

    def test_no_san_extension(self):
        """Test certificate without SAN extension."""
        cert_info = {"subject": {"commonName": "example.com"}}
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is False
        assert "Subject Alternative Name extension" in result["reason"]
        assert result["sans"] is None
        assert result["count"] == 0

    def test_san_dict_format(self):
        """Test SAN in dictionary format."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com", "www.example.com"],
                "IP Address": ["192.168.1.1", "10.0.0.1"],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert result["count"] == 4
        assert len(result["sans"]["DNS"]) == 2
        assert len(result["sans"]["IP Address"]) == 2

    def test_san_list_format(self):
        """Test SAN in list format."""
        cert_info = {
            "subjectAltName": [
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
                ("IP Address", "192.168.1.1"),
            ]
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert result["count"] == 3
        assert "example.com" in result["sans"]["DNS"]
        assert "192.168.1.1" in result["sans"]["IP Address"]

    def test_ip_address_validation_success(self):
        """Test IP address validation success."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com"],
                "IP Address": ["192.168.1.1", "10.0.0.1"],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "192.168.1.1", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert "Exact match for IP 192.168.1.1" in result["contains_host"]["reason"]

    def test_ip_address_validation_failure(self):
        """Test IP address validation failure."""
        cert_info = {
            "subjectAltName": {"DNS": ["example.com"], "IP Address": ["192.168.1.1"]}
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "10.0.0.1", 443)
        assert result["is_valid"] is True  # Overall still valid (has SANs)
        assert result["contains_host"]["is_valid"] is False
        assert "No match found for IP 10.0.0.1" in result["contains_host"]["reason"]
        assert "10.0.0.1" in result["warnings"][0]

    def test_wildcard_dns_match(self):
        """Test wildcard DNS matching."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["*.example.com", "example.com"],
                "IP Address": [],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert "matches wildcard SAN" in result["contains_host"]["reason"]
        assert "*.example.com" in result["contains_host"]["reason"]

    def test_wildcard_no_match(self):
        """Test wildcard that doesn't match."""
        cert_info = {"subjectAltName": {"DNS": ["*.example.com"], "IP Address": []}}
        validator = SubjectAltNamesValidator()
        result = validator.validate(
            {"cert_info": cert_info}, "sub.www.example.com", 443
        )
        assert result["is_valid"] is True  # Overall valid (has SANs)
        assert result["contains_host"]["is_valid"] is False
        assert (
            "No match found for sub.www.example.com"
            in result["contains_host"]["reason"]
        )

    def test_exact_dns_match(self):
        """Test exact DNS matching."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com", "www.example.com"],
                "IP Address": [],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert "Exact match for example.com" in result["contains_host"]["reason"]

    def test_no_dns_or_ip_sans_warning(self):
        """Test warning when no DNS or IP SANs are present."""
        cert_info = {"subjectAltName": {"DNS": [], "IP Address": []}}
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "example.com", 443)
        assert result["is_valid"] is True
        assert result["count"] == 0
        assert (
            "Certificate does not contain any DNS or IP Address SANs"
            in result["warnings"]
        )

    def test_high_san_count_warning(self):
        """Test warning for unusually high number of SANs."""
        # Create a cert with 101 DNS SANs to trigger the warning
        dns_sans = [f"test{i}.example.com" for i in range(101)]
        cert_info = {"subjectAltName": {"DNS": dns_sans, "IP Address": []}}
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "test0.example.com", 443)
        assert result["is_valid"] is True
        assert result["count"] == 101
        assert any(
            "unusually high number of SANs" in warning for warning in result["warnings"]
        )

    def test_alternate_names_validation(self):
        """Test validation of alternate names."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com", "www.example.com"],
                "IP Address": ["192.168.1.1"],
            }
        }
        validator = SubjectAltNamesValidator()
        alternate_names = ["www.example.com", "192.168.1.1", "invalid.com"]
        result = validator.validate(
            {"cert_info": cert_info}, "example.com", 443, alternate_names
        )

        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True

        # Check alternate name validations
        assert result["contains_alternate"]["www.example.com"]["is_valid"] is True
        assert result["contains_alternate"]["192.168.1.1"]["is_valid"] is True
        assert result["contains_alternate"]["invalid.com"]["is_valid"] is False

        # Should have warning for invalid.com
        assert any("invalid.com" in warning for warning in result["warnings"])

    def test_wildcard_matching_logic(self):
        """Test _matches_wildcard method directly."""
        validator = SubjectAltNamesValidator()

        # Valid wildcard matches
        assert validator._matches_wildcard("www.example.com", "*.example.com") is True
        assert validator._matches_wildcard("sub.test.com", "*.test.com") is True

        # Invalid matches
        assert (
            validator._matches_wildcard("www.example.com", "example.com") is False
        )  # No wildcard
        assert (
            validator._matches_wildcard("sub.www.example.com", "*.example.com") is False
        )  # Too many levels
        assert (
            validator._matches_wildcard("www.other.com", "*.example.com") is False
        )  # Different domain

    def test_ipv6_address_validation(self):
        """Test IPv6 address validation."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com"],
                "IP Address": ["2001:db8::1", "::1"],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "2001:db8::1", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert "Exact match for IP 2001:db8::1" in result["contains_host"]["reason"]

    def test_invalid_ip_address_parsing(self):
        """Test handling of invalid IP addresses in SANs."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["example.com"],
                "IP Address": ["not.an.ip"],  # Invalid IP
            }
        }
        validator = SubjectAltNamesValidator()
        # This should be handled gracefully
        result = validator.validate({"cert_info": cert_info}, "192.168.1.1", 443)
        assert result["is_valid"] is True  # Overall valid
        assert result["contains_host"]["is_valid"] is False  # But host doesn't match

    def test_multiple_wildcard_matches(self):
        """Test multiple wildcard patterns matching."""
        cert_info = {
            "subjectAltName": {
                "DNS": ["*.example.com", "*.test.example.com"],
                "IP Address": [],
            }
        }
        validator = SubjectAltNamesValidator()
        result = validator.validate({"cert_info": cert_info}, "www.example.com", 443)
        assert result["is_valid"] is True
        assert result["contains_host"]["is_valid"] is True
        assert "matches wildcard SAN" in result["contains_host"]["reason"]

    def test_check_name_in_sans_with_reason_dns(self):
        """Test _check_name_in_sans_with_reason method for DNS names."""
        validator = SubjectAltNamesValidator()
        dns_sans = ["example.com", "*.test.com"]
        ip_sans = ["192.168.1.1"]

        # Exact DNS match
        is_valid, reason = validator._check_name_in_sans_with_reason(
            "example.com", dns_sans, ip_sans
        )
        assert is_valid is True
        assert "Exact match for example.com" in reason

        # Wildcard DNS match
        is_valid, reason = validator._check_name_in_sans_with_reason(
            "www.test.com", dns_sans, ip_sans
        )
        assert is_valid is True
        assert "matches wildcard SAN" in reason

        # No match
        is_valid, reason = validator._check_name_in_sans_with_reason(
            "invalid.com", dns_sans, ip_sans
        )
        assert is_valid is False
        assert "No match found for invalid.com" in reason

    def test_check_name_in_sans_with_reason_ip(self):
        """Test _check_name_in_sans_with_reason method for IP addresses."""
        validator = SubjectAltNamesValidator()
        dns_sans = ["example.com"]
        ip_sans = ["192.168.1.1", "10.0.0.1"]

        # Valid IP match
        is_valid, reason = validator._check_name_in_sans_with_reason(
            "192.168.1.1", dns_sans, ip_sans
        )
        assert is_valid is True
        assert "Exact match for IP 192.168.1.1" in reason

        # Invalid IP no match
        is_valid, reason = validator._check_name_in_sans_with_reason(
            "172.16.0.1", dns_sans, ip_sans
        )
        assert is_valid is False
        assert "No match found for IP 172.16.0.1" in reason
