# tests/test_validators/test_sensitive_date.py

"""
Tests for SensitiveDateValidator.
"""

from datetime import date
import pytest
from certmonitor.validators.sensitive_date import SensitiveDate, SensitiveDateValidator


def test_leapdayexpiry(sample_cert):
    """Cert expires on leap day — should flag and be invalid."""
    sample_cert["notAfter"] = "Feb 29 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert not result["is_valid"]
    assert not result["weekend_expiry"]
    assert result["leapday_expiry"]
    assert not result["warnings"]


def test_not_leapday_expiry(sample_cert):
    """Cert expires on non-leap day — no flag, should be valid."""
    sample_cert["notAfter"] = "Mar  1 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"]
    assert not result["weekend_expiry"]
    assert not result["leapday_expiry"]
    assert not result["warnings"]


def test_weekend_expiry(sample_cert):
    """Cert expires on weekend — should flag and be invalid."""
    sample_cert["notAfter"] = "Mar  4 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert not result["is_valid"]
    assert result["weekend_expiry"]
    assert not result["leapday_expiry"]
    assert not result["warnings"]


def test_not_weekend_expiry(sample_cert):
    """Cert expires on weekday — no flag, should be valid."""
    sample_cert["notAfter"] = "Mar  1 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"]
    assert not result["weekend_expiry"]
    assert not result["leapday_expiry"]
    assert not result["warnings"]


def test_sensitive_date_warning_and_invalid(sample_cert):
    """Cert expires on sensitive date — warning should appear and cert should be invalid."""
    sample_cert["notAfter"] = "Nov 16 23:59:59 2025 GMT"  # Sunday
    validator = SensitiveDateValidator()
    sensitive_date = SensitiveDate("Busy Sunday", date(2025, 11, 16))

    result = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, sensitive_date
    )

    expected_warning = (
        'Certificate is due to expire on sensitive date "Busy Sunday" (2025-11-16)'
    )

    assert not result["is_valid"]
    assert result["weekend_expiry"]
    assert not result["leapday_expiry"]
    assert expected_warning in result["warnings"]


def test_sensitive_date_no_warning_and_valid(sample_cert):
    """Cert expires on a non-sensitive weekday — no warning, cert should be valid."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"  # Monday
    validator = SensitiveDateValidator()
    sensitive_date = SensitiveDate("Busy Tuesday", date(2025, 11, 18))

    result = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, sensitive_date
    )

    assert result["is_valid"]
    assert not result["weekend_expiry"]
    assert not result["leapday_expiry"]
    assert not result["warnings"]


def test_sensitive_date_validator_type_check(sample_cert):
    """Passing non-SensitiveDate args raises TypeError."""
    validator = SensitiveDateValidator()

    with pytest.raises(TypeError) as excinfo:
        validator.validate(
            {"cert_info": sample_cert},
            "www.example.com",
            443,
            SensitiveDate("Valid SensitiveDate", date(2025, 1, 1)),
            "A string not a SensitiveDate",
        )

    assert "Expected SensitiveDate, got str" in str(excinfo.value)


if __name__ == "__main__":
    pytest.main()
