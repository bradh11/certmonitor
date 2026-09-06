from datetime import datetime, timedelta, timezone
import pytest
from certmonitor.validators.expiration import ExpirationValidator


def certificate(start=-1, end=30):
    now = datetime.now(timezone.utc)
    return {
        "cert_info": {
            "notBefore": (now + timedelta(days=start)).strftime(
                "%b %d %H:%M:%S %Y GMT"
            ),
            "notAfter": (now + timedelta(days=end)).strftime("%b %d %H:%M:%S %Y GMT"),
        }
    }


@pytest.mark.parametrize(
    "start,end,valid", [(-1, 30, True), (-2, -1, False), (1, 30, False)]
)
def test_validity_boundaries(start, end, valid):
    result = ExpirationValidator().validate(certificate(start, end), "example.com", 443)
    assert result["is_valid"] is valid
    if not valid:
        assert result["reason"]


def test_twelve_hours_triggers_critical_warning():
    result = ExpirationValidator().validate(certificate(end=0.5), "example.com", 443)
    assert result["is_valid"] is True
    assert result["days_to_expiry"] == 0
    assert "critical" in result["warnings"][0]


def test_warning_threshold_is_configurable():
    result = ExpirationValidator().validate(
        certificate(end=20), "example.com", 443, warning_days=30
    )
    assert "warning threshold" in result["warnings"][0]


def test_lifetime_policy_uses_total_not_remaining():
    result = ExpirationValidator().validate(
        certificate(start=-190, end=20), "example.com", 443, max_lifetime_days=200
    )
    assert result["is_valid"] is True
    assert result["lifetime_days"] == 210
    assert "total lifetime" in result["warnings"][0]


def test_default_policy_follows_the_public_tls_schedule():
    # Issued after March 2026: the 200-day step applies.
    recent = ExpirationValidator().validate(
        certificate(start=-1, end=364), "example.com", 443
    )
    assert recent["lifetime_limit_days"] == 200
    assert "exceeds the 200-day public TLS limit" in recent["warnings"][0]
    assert recent["is_valid"] is True
    within = ExpirationValidator().validate(
        certificate(start=-1, end=180), "example.com", 443
    )
    assert within["warnings"] == []


def test_schedule_uses_the_limit_in_force_on_the_issue_date():
    from datetime import date

    from certmonitor.validators.expiration import public_tls_lifetime_limit

    assert public_tls_lifetime_limit(date(2017, 12, 1)) == 1187
    assert public_tls_lifetime_limit(date(2019, 6, 1)) == 825
    assert public_tls_lifetime_limit(date(2021, 1, 1)) == 398
    assert public_tls_lifetime_limit(date(2026, 3, 15)) == 200
    assert public_tls_lifetime_limit(date(2027, 3, 15)) == 100
    assert public_tls_lifetime_limit(date(2029, 3, 15)) == 47
    # A 2025 certificate with 390 days was compliant then and is not flagged now.
    old = ExpirationValidator().validate(
        certificate(start=-500, end=-110), "example.com", 443
    )
    assert old["lifetime_limit_days"] == 398
    assert not any("lifetime" in w for w in old["warnings"])


def test_lifetime_policy_can_be_relaxed_or_disabled():
    cert = certificate(start=-1, end=500)
    relaxed = ExpirationValidator().validate(
        cert, "example.com", 443, max_lifetime_days=1000
    )
    assert relaxed["warnings"] == []
    assert relaxed["lifetime_limit_days"] == 1000
    disabled = ExpirationValidator().validate(
        cert, "example.com", 443, max_lifetime_days=None
    )
    assert disabled["warnings"] == []
    assert "lifetime_limit_days" not in disabled


def test_expired_reason_survives_lifetime_policy():
    result = ExpirationValidator().validate(
        certificate(start=-500, end=-3), "example.com", 443
    )
    assert result["is_valid"] is False
    assert result["reason"].startswith("Certificate expired")
    assert "days ago" in result["reason"]
    assert any("total lifetime" in warning for warning in result["warnings"])


def test_missing_not_before_skips_start_and_lifetime_checks():
    cert = certificate(end=90)
    del cert["cert_info"]["notBefore"]
    result = ExpirationValidator().validate(cert, "example.com", 443)
    assert result["is_valid"] is True
    assert result["warnings"] == []
    assert "lifetime_days" not in result


@pytest.mark.parametrize(
    "kwargs",
    [
        {"warning_days": -1},
        {"critical_days": 10},
        {"max_lifetime_days": 0},
        {"max_lifetime_days": "forever"},
    ],
)
def test_invalid_policy(kwargs):
    with pytest.raises(ValueError):
        ExpirationValidator().validate(certificate(), "example.com", 443, **kwargs)
