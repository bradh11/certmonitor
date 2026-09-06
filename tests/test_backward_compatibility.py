"""Public calling conventions and result fields retained across the security fixes."""

from types import MappingProxyType
from unittest.mock import MagicMock

import pytest

from certmonitor import CertMonitor
from certmonitor.validators.base import BaseCertValidator
from certmonitor.validators.hostname import HostnameValidator


def test_original_constructor_and_defaults():
    monitor = CertMonitor("example.com", 8443, ["hostname"])
    assert monitor.host == "example.com"
    assert monitor.port == 8443
    assert monitor.get_enabled_validators() == ["hostname"]
    assert CertMonitor("example.com").get_enabled_validators() == [
        "expiration",
        "hostname",
        "root_certificate",
    ]


def test_close_keeps_snapshot_available_without_network():
    monitor = CertMonitor("example.com")
    monitor.connected = True
    monitor.handler = MagicMock()
    snapshot = {"subjectAltName": {"DNS": ["example.com"]}}
    monitor.cert_info = snapshot
    monitor.cert_data = {"cert_info": snapshot}
    monitor.der = b"collected certificate"
    monitor.snapshot_at = "2026-09-04T00:00:00+00:00"
    monitor.close()
    assert monitor.connected is False
    assert monitor.handler is None
    assert monitor.get_cert_info() is snapshot
    assert monitor.der == b"collected certificate"
    assert monitor.snapshot_at


def test_close_resets_connection_even_if_handler_raises():
    monitor = CertMonitor("example.com")
    monitor.handler = MagicMock()
    monitor.handler.close.side_effect = OSError("already closed")
    monitor.connected = True
    with pytest.raises(OSError):
        monitor.close()
    assert monitor.handler is None
    assert monitor.connected is False


def test_reconnect_keeps_snapshot_and_refresh_discards_it(monkeypatch):
    monitor = CertMonitor("example.com")
    monitor.cert_data = {"cert_info": {"retained": True}}
    monitor.cert_info = {"retained": True}
    monitor.der = b"retained"
    monkeypatch.setattr(
        monitor, "detect_protocol", MagicMock(return_value={"error": "ConnectionError"})
    )
    assert monitor.connect()["error"] == "ConnectionError"
    assert monitor.cert_data == {"cert_info": {"retained": True}}
    assert monitor.der == b"retained"
    assert monitor.refresh()["error"] == "ConnectionError"
    assert monitor.cert_info is None and monitor.der is None
    assert monitor.cert_data == {}


def test_cipher_access_after_close_keeps_certificate_snapshot(monkeypatch):
    """A cipher-only reconnect after close() must not wipe the retained snapshot."""
    monitor = CertMonitor(
        "example.com",
        enabled_validators=["hostname", "root_certificate", "weak_cipher"],
    )
    snapshot = {"subjectAltName": {"DNS": ["example.com"]}}
    monitor.cert_info = snapshot
    monitor.cert_data = {"cert_info": snapshot}
    monitor.der = b"collected certificate"
    monitor.snapshot_at = "2026-09-04T00:00:00+00:00"
    monitor.protocol = "ssl"
    handler = MagicMock()
    handler.fetch_raw_cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def connect():
        monitor.handler, monitor.connected = handler, True

    monkeypatch.setattr(monitor, "connect", connect)
    monkeypatch.setattr(
        monitor,
        "_verify_trust",
        MagicMock(
            return_value={"is_valid": True, "status": "pass", "trust_verified": True}
        ),
    )
    results = monitor.validate()
    assert results["weak_cipher"]["is_valid"] is True
    assert results["hostname"]["is_valid"] is True
    assert monitor.cert_data["cert_info"] is snapshot
    assert monitor.der == b"collected certificate"
    assert monitor.snapshot_at == "2026-09-04T00:00:00+00:00"


@pytest.mark.parametrize(
    "raw",
    [
        (
            ("DNS", "example.com"),
            ("email", "admin@example.com"),
            ("URI", "https://example.com/id"),
        ),
        {
            "DNS": "example.com",
            "email": "admin@example.com",
            "URI": ["https://example.com/id"],
        },
    ],
)
def test_certificate_collection_preserves_other_san_types(raw):
    info = CertMonitor("example.com")._to_structured_dict({"subjectAltName": raw})
    assert info["subjectAltName"]["DNS"] == ["example.com"]
    assert info["subjectAltName"]["email"] == ["admin@example.com"]
    assert info["subjectAltName"]["URI"] == ["https://example.com/id"]


def test_hostname_wildcard_matched_name_remains_pattern():
    result = HostnameValidator().validate(
        {"cert_info": {"subjectAltName": {"DNS": ["*.example.com"]}}},
        "api.example.com",
        443,
    )
    assert result["is_valid"] is True
    assert result["matched_name"] == "*.example.com"
    assert result["alt_names"] == ["*.example.com"]


@pytest.mark.parametrize("readonly", [False, True])
def test_custom_validator_result_is_not_mutated(readonly):
    original = {"is_valid": True, "custom_field": 17}
    returned = MappingProxyType(original) if readonly else original

    class CustomValidator(BaseCertValidator):
        name = "custom"

        def validate(self, cert: dict, host: str, port: int) -> dict:
            return returned

    monitor = CertMonitor("example.com", enabled_validators=["custom"])
    monitor.cert_data = {"cert_info": {}}
    monitor.validators = {"custom": CustomValidator()}
    result = monitor.validate()["custom"]
    assert result["custom_field"] == 17
    assert result["status"] == "pass"
    assert original == {"is_valid": True, "custom_field": 17}


def test_trust_result_preserves_issuer_and_warnings(monkeypatch):
    monitor = CertMonitor("example.com", enabled_validators=["root_certificate"])
    issuer = {"commonName": "Configured CA"}
    monitor.cert_data = {"cert_info": {"issuer": issuer}}
    monkeypatch.setattr(
        monitor,
        "_verify_trust",
        MagicMock(
            return_value={"is_valid": True, "status": "pass", "trust_verified": True}
        ),
    )
    result = monitor.validate()["root_certificate"]
    assert result["issuer"] == issuer
    assert result["warnings"] == []


def test_legacy_alternate_names_list_still_dispatches():
    monitor = CertMonitor("primary.test", enabled_validators=["subject_alt_names"])
    monitor.cert_data = {"cert_info": {"subjectAltName": {"DNS": "alternate.test"}}}
    with pytest.warns(DeprecationWarning):
        legacy = monitor.validate({"subject_alt_names": ["alternate.test"]})
    canonical = monitor.validate(
        {"subject_alt_names": {"alternate_names": ["alternate.test"]}}
    )
    assert legacy == canonical
    assert legacy["subject_alt_names"]["is_valid"] is True
