# tests/test_validators/test_expiration.py

from datetime import datetime, timedelta

from certmonitor.validators.expiration import ExpirationValidator


def test_expiration_validator(sample_cert):
    validator = ExpirationValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    assert result["is_valid"]
    assert "days_to_expiry" in result


def test_expired_cert(sample_cert):
    sample_cert["notAfter"] = (datetime.now() - timedelta(days=1)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )
    validator = ExpirationValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    assert not result["is_valid"]


def test_expiration_validator_certificate_too_long():
    """Test expiration validator with certificate valid for more than 398 days to cover line 72."""
    from datetime import datetime, timedelta

    from certmonitor.validators.expiration import ExpirationValidator

    validator = ExpirationValidator()

    # Create mock certificate data with expiry more than 398 days in future
    future_date = datetime.now() + timedelta(days=500)  # 500 days in future

    mock_cert_data = {
        "cert_info": {"notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT")}
    }

    result = validator.validate(mock_cert_data, "example.com", 443)

    # Should have a warning about certificate being valid for too long
    assert isinstance(result, dict)
    assert "warnings" in result
    warnings = result["warnings"]
    assert any(
        "valid for more than industry standard" in warning for warning in warnings
    )


def test_expiration_long_validity_certificate():
    """Test certificate with validity > 398 days to ensure comprehensive coverage."""
    from datetime import timezone

    validator = ExpirationValidator()

    # Create a certificate with exactly 400 days validity to ensure we hit the > 398 condition
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=400)  # Exactly 400 days from now

    cert_data = {
        "cert_info": {
            "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        }
    }

    result = validator.validate(cert_data, "example.com", 443)

    # Verify we get the warning about industry standard
    assert result["is_valid"] is True
    assert "warnings" in result

    # Check that we have a warning about industry standard
    industry_warning_found = any(
        "more than industry standard" in warning for warning in result["warnings"]
    )
    assert industry_warning_found


if __name__ == "__main__":
    import pytest

    pytest.main()
