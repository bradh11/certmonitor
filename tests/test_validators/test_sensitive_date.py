# tests/test_validators/test_sensitive_date.py

"""
Tests for SensitiveDateValidator.
"""

from datetime import date, datetime

import pytest

from certmonitor.validators.sensitive_date import SensitiveDate, SensitiveDateValidator


def test_leapday_expiry_flag_and_warning(sample_cert):
    """Cert expires on leap day — flag set and warning emitted."""
    sample_cert["notAfter"] = "Feb 29 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"] is False
    assert result["leapday_expiry"] is True
    assert result["weekend_expiry"] is False
    assert result["sensitive_date_matches"] == []
    assert any("leap day" in w for w in result["warnings"])


def test_not_leapday_expiry(sample_cert):
    """Cert expires on non-leap day — no flag, should be valid."""
    sample_cert["notAfter"] = "Mar  1 23:59:59 2028 GMT"
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"] is True
    assert result["weekend_expiry"] is False
    assert result["leapday_expiry"] is False
    assert result["warnings"] == []


def test_weekend_expiry_flag_and_warning(sample_cert):
    """Cert expires on Saturday — flag set and warning emitted with day name."""
    sample_cert["notAfter"] = "Mar  4 23:59:59 2028 GMT"  # Saturday
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"] is False
    assert result["weekend_expiry"] is True
    assert result["leapday_expiry"] is False
    assert result["sensitive_date_matches"] == []
    assert any("weekend (Saturday)" in w for w in result["warnings"])


def test_sunday_weekend_warning(sample_cert):
    """Sunday expiry gets a ``Sunday`` warning string."""
    sample_cert["notAfter"] = "Nov 16 23:59:59 2025 GMT"  # Sunday
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["weekend_expiry"] is True
    assert any("weekend (Sunday)" in w for w in result["warnings"])


def test_not_weekend_expiry(sample_cert):
    """Cert expires on weekday — no flag, should be valid."""
    sample_cert["notAfter"] = "Mar  1 23:59:59 2028 GMT"  # Wednesday
    validator = SensitiveDateValidator()
    result = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)

    assert result["is_valid"] is True
    assert result["weekend_expiry"] is False
    assert result["leapday_expiry"] is False
    assert result["warnings"] == []


def test_sensitive_date_match_with_sensitive_date_nt(sample_cert):
    """Matching a SensitiveDate NamedTuple produces a structured match entry."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"  # Monday
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[SensitiveDate("Busy Monday", date(2025, 11, 17))],
    )

    assert result["is_valid"] is False
    assert result["weekend_expiry"] is False
    assert result["leapday_expiry"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "Busy Monday", "date": "2025-11-17"}
    ]
    assert any('sensitive date "Busy Monday"' in w for w in result["warnings"])


def test_sensitive_date_match_with_bare_date(sample_cert):
    """A bare ``date`` is accepted; name defaults to the ISO string."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[date(2025, 11, 17)],
    )

    assert result["is_valid"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "2025-11-17", "date": "2025-11-17"}
    ]


def test_sensitive_date_match_with_iso_string(sample_cert):
    """An ISO date string is accepted; name defaults to the string itself."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=["2025-11-17"],
    )

    assert result["is_valid"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "2025-11-17", "date": "2025-11-17"}
    ]


def test_sensitive_date_match_with_name_date_tuple(sample_cert):
    """A ``(name, date)`` tuple is unpacked into a SensitiveDate."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[("Launch Day", date(2025, 11, 17))],
    )

    assert result["is_valid"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "Launch Day", "date": "2025-11-17"}
    ]


def test_tuple_with_datetime_second_element(sample_cert):
    """A ``(name, datetime)`` tuple is normalized — datetime is truncated to date."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[("Launch Day", datetime(2025, 11, 17, 9, 0))],
    )

    assert result["is_valid"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "Launch Day", "date": "2025-11-17"}
    ]


def test_sensitive_date_match_with_datetime(sample_cert):
    """A ``datetime`` is truncated to its date component."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[datetime(2025, 11, 17, 13, 30)],
    )

    assert result["is_valid"] is False
    assert result["sensitive_date_matches"] == [
        {"name": "2025-11-17", "date": "2025-11-17"}
    ]


def test_mixed_input_forms_in_one_call(sample_cert):
    """All four input forms can be combined in the same ``dates`` list."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[
            SensitiveDate("NT form", date(2025, 11, 17)),
            date(2025, 11, 17),
            "2025-11-17",
            ("Tuple form", date(2025, 11, 17)),
        ],
    )

    assert result["is_valid"] is False
    assert len(result["sensitive_date_matches"]) == 4
    names = {m["name"] for m in result["sensitive_date_matches"]}
    assert names == {"NT form", "2025-11-17", "Tuple form"}


def test_sensitive_date_no_match_valid(sample_cert):
    """Cert expires on a weekday not in the list — valid, no warnings."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"  # Monday
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[SensitiveDate("Busy Tuesday", date(2025, 11, 18))],
    )

    assert result["is_valid"] is True
    assert result["sensitive_date_matches"] == []
    assert result["warnings"] == []


def test_multiple_sensitive_date_matches(sample_cert):
    """Every matching sensitive date shows up in both structured and warning output."""
    sample_cert["notAfter"] = "Nov 17 23:59:59 2025 GMT"  # Monday
    validator = SensitiveDateValidator()
    sensitive_dates = [
        SensitiveDate(f"Day {i + 1}", date(2025, 11, (i % 30) + 1)) for i in range(100)
    ]

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=sensitive_dates,
    )

    # Nov 17 is index 16, 46, 76 in the rotating-30 scheme.
    expected_names = {"Day 17", "Day 47", "Day 77"}
    assert result["is_valid"] is False
    assert result["weekend_expiry"] is False
    assert result["leapday_expiry"] is False

    match_names = {m["name"] for m in result["sensitive_date_matches"]}
    assert expected_names <= match_names
    for name in expected_names:
        assert any(f'"{name}"' in w for w in result["warnings"])


def test_invalid_input_type_returns_error_dict(sample_cert):
    """A non-supported type (e.g. ``int``) returns a structured error, not an exception."""
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[42],  # type: ignore[list-item]
    )

    assert result["is_valid"] is False
    assert "Invalid sensitive date input" in result["reason"]
    assert "int" in result["reason"]


def test_invalid_iso_string_returns_error_dict(sample_cert):
    """A malformed ISO date string returns a structured error."""
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=["not-a-date"],
    )

    assert result["is_valid"] is False
    assert "Invalid sensitive date input" in result["reason"]


def test_tuple_with_non_date_second_element_returns_error_dict(sample_cert):
    """A ``(name, not-a-date)`` tuple returns a structured error."""
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert},
        "www.example.com",
        443,
        dates=[("Launch Day", "not a date")],  # type: ignore[list-item]
    )

    assert result["is_valid"] is False
    assert "Invalid sensitive date input" in result["reason"]


def test_empty_dates_list_still_runs_weekend_leapday_checks(sample_cert):
    """Passing ``dates=[]`` still runs weekend/leap-day checks."""
    sample_cert["notAfter"] = "Nov 16 23:59:59 2025 GMT"  # Sunday
    validator = SensitiveDateValidator()

    result = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, dates=[]
    )

    assert result["is_valid"] is False
    assert result["weekend_expiry"] is True
    assert result["sensitive_date_matches"] == []


def test_dates_none_is_equivalent_to_not_provided(sample_cert):
    """``dates=None`` is equivalent to not passing ``dates`` at all."""
    sample_cert["notAfter"] = "Mar  1 23:59:59 2028 GMT"  # Wednesday
    validator = SensitiveDateValidator()

    result_a = validator.validate({"cert_info": sample_cert}, "www.example.com", 443)
    result_b = validator.validate(
        {"cert_info": sample_cert}, "www.example.com", 443, dates=None
    )

    assert result_a == result_b


if __name__ == "__main__":
    pytest.main()
