from certmonitor.validators.hostname import HostnameValidator


def test_hostname_validator(sample_cert):
    validator = HostnameValidator()
    result = validator.validate(sample_cert, "www.example.com", 443)
    assert result["is_valid"] == True


def test_hostname_validator_mismatch(sample_cert):
    validator = HostnameValidator()
    result = validator.validate(sample_cert, "invalid.com", 443)
    assert result["is_valid"] == False
