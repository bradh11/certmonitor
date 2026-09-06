import pytest

from certmonitor.validators.hostname import HostnameValidator


@pytest.mark.parametrize(
    "cn,san,host,valid,cn_matches",
    [
        ("example.com", "example.com", "example.com", True, True),
        ("example.com", "other.test", "example.com", False, True),
        ("other.test", "example.com", "example.com", True, False),
        ("example.com", None, "example.com", False, True),
        (None, "example.com", "example.com", True, False),
        ("*.example.com", "*.example.com", "API.EXAMPLE.COM", True, True),
        ("*.example.com", "*.example.com", "a.b.example.com", False, False),
        ("*.example.com", "*.example.com", "example.com", False, False),
    ],
)
def test_san_identity_with_informational_cn(cn, san, host, valid, cn_matches):
    result = HostnameValidator().validate(
        {
            "cert_info": {
                "subject": {"commonName": cn},
                "subjectAltName": {"DNS": [san] if san else []},
            }
        },
        host,
        443,
    )
    assert result["is_valid"] is valid
    assert result["common_name_matches"] is cn_matches
    assert result["identity_source"] == "subjectAltName"
    if not valid:
        assert result["reason"]


def test_raw_subject_format():
    result = HostnameValidator().validate(
        {
            "cert_info": {
                "subject": ((("commonName", "example.com"),),),
                "subjectAltName": (("DNS", "example.com"),),
            }
        },
        "example.com",
        443,
    )
    assert result["is_valid"] is True
    assert result["common_name_matches"] is True


@pytest.mark.parametrize(
    "sans,host,expected",
    [
        (
            {"DNS": ["api.example.com", "*.example.com"]},
            "api.example.com",
            "api.example.com",
        ),
        (
            {"DNS": ["*.example.com", "api.example.com"]},
            "api.example.com",
            "*.example.com",
        ),
        ({"DNS": ["*.example.com"]}, "www.example.com", "*.example.com"),
        ({"IP Address": ["192.0.2.1"]}, "192.0.2.1", "192.0.2.1"),
    ],
)
def test_matched_name_is_the_san_that_matched(sans, host, expected):
    result = HostnameValidator().validate(
        {"cert_info": {"subjectAltName": sans}}, host, 443
    )
    assert result["is_valid"] is True
    assert result["matched_name"] == expected


def test_non_string_san_entries_are_ignored():
    result = HostnameValidator().validate(
        {"cert_info": {"subjectAltName": {"DNS": ["example.com", None]}}},
        "example.com",
        443,
    )
    assert result["is_valid"] is True
    assert result["alt_names"] == ["example.com"]


def test_expected_identity_overrides_the_connection_host():
    cert = {"cert_info": {"subjectAltName": {"DNS": ["api.example.com"]}}}
    result = HostnameValidator().validate(
        cert, "10.0.0.5", 443, expected_identity="api.example.com"
    )
    assert result["is_valid"] is True
    assert result["matched_name"] == "api.example.com"
    assert HostnameValidator().validate(cert, "10.0.0.5", 443)["is_valid"] is False
