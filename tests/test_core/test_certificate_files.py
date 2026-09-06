"""Certificates loaded from files or bytes validate without a connection."""

import ssl
from pathlib import Path

import pytest

from certmonitor import CertMonitor
from certmonitor.validators import VALIDATORS

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CHAIN_DER = [(FIXTURES / f"chain_{i}.der").read_bytes() for i in range(3)]
LEAF_HOST = "www.google.com"
LIVE_ONLY = {"tls_version", "weak_cipher", "root_certificate", "pq_key_exchange"}


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "chain.pem"
    path.write_text("".join(ssl.DER_cert_to_PEM_cert(der) for der in CHAIN_DER))
    return path


@pytest.fixture
def leaf_der(tmp_path):
    path = tmp_path / "leaf.der"
    path.write_bytes(CHAIN_DER[0])
    return path


def test_pem_bundle_loads_leaf_and_chain(bundle):
    with CertMonitor.from_file(bundle, host=LEAF_HOST) as monitor:
        info = monitor.get_cert_info()
        assert info["subject"]["commonName"] == LEAF_HOST
        assert monitor.der == CHAIN_DER[0]
        assert monitor.cert_data["chain_der"] == CHAIN_DER
        assert monitor.cert_data["chain_analysis"]["chain_length"] == 3
        assert monitor.cert_data["source"] == {"type": "file", "path": str(bundle)}
        assert monitor.snapshot_at
        assert monitor.offline is True
        assert monitor.get_public_key_pem().startswith("-----BEGIN PUBLIC KEY-----")


def test_der_file_loads_a_single_certificate(leaf_der):
    with CertMonitor.from_file(leaf_der, host=LEAF_HOST) as monitor:
        assert monitor.get_cert_info()["subject"]["commonName"] == LEAF_HOST
        assert monitor.cert_data["chain_der"] == [CHAIN_DER[0]]
        assert monitor.get_raw_pem() == ssl.DER_cert_to_PEM_cert(CHAIN_DER[0])


def test_every_validator_returns_a_result_offline(bundle):
    with CertMonitor.from_file(
        bundle, host=LEAF_HOST, enabled_validators=list(VALIDATORS)
    ) as monitor:
        results = monitor.validate()
    assert set(results) == set(VALIDATORS)
    for name in LIVE_ONLY:
        assert results[name]["status"] == "unsupported", results[name]
        assert "live connection" in results[name]["reason"]
    for name in set(VALIDATORS) - LIVE_ONLY:
        assert results[name]["status"] != "error", results[name]
    assert results["hostname"]["is_valid"] is True
    assert results["key_info"]["is_valid"] is True
    assert results["chain"]["chain_length"] == 3
    assert results["pq_signature"]["is_pq"] is False
    assert results["subject_alt_names"]["contains_host"]["is_valid"] is True


def test_identity_checks_need_a_host(bundle):
    with CertMonitor.from_file(
        bundle, enabled_validators=["hostname", "subject_alt_names", "expiration"]
    ) as monitor:
        results = monitor.validate()
        assert results["hostname"]["status"] == "unsupported"
        assert results["subject_alt_names"]["status"] == "unsupported"
        assert results["expiration"]["status"] in ("pass", "warn", "fail")
        named = monitor.validate(
            {
                "hostname": {"expected_identity": LEAF_HOST},
                "subject_alt_names": {"alternate_names": [LEAF_HOST]},
            }
        )
        assert named["hostname"]["is_valid"] is True
        assert named["subject_alt_names"]["is_valid"] is True


def test_cipher_info_is_unsupported_offline(bundle):
    with CertMonitor.from_file(bundle, host=LEAF_HOST) as monitor:
        cipher = monitor.get_cipher_info()
    assert cipher["error"] == "OfflineSource"
    assert "live connection" in cipher["message"]


def test_from_bytes_accepts_pem_text_and_der_bytes():
    pem = ssl.DER_cert_to_PEM_cert(CHAIN_DER[0])
    for data in (pem, pem.encode(), CHAIN_DER[0]):
        monitor = CertMonitor.from_bytes(data, host=LEAF_HOST)
        assert monitor.get_cert_info()["subject"]["commonName"] == LEAF_HOST
        assert monitor.cert_data["source"] == {"type": "bytes"}


def test_refresh_rereads_the_file(bundle):
    with CertMonitor.from_file(bundle, host=LEAF_HOST) as monitor:
        assert monitor.get_cert_info()["subject"]["commonName"] == LEAF_HOST
        bundle.write_text(ssl.DER_cert_to_PEM_cert(CHAIN_DER[1]))
        monitor.refresh()
        assert monitor.get_cert_info()["subject"]["commonName"] == "WR2"
        assert monitor.der == CHAIN_DER[1]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not a certificate",
        b"-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n",
    ],
)
def test_unreadable_content_is_a_certificate_error(tmp_path, content):
    path = tmp_path / "bad.pem"
    path.write_bytes(content)
    monitor = CertMonitor.from_file(path, host=LEAF_HOST)
    info = monitor.get_cert_info()
    assert info["error"] == "CertificateError"
    results = monitor.validate()
    assert results["expiration"]["status"] == "error"
    assert results["expiration"]["error"] == "CertificateError"


def test_missing_file_is_a_certificate_error(tmp_path):
    monitor = CertMonitor.from_file(tmp_path / "nope.pem", host=LEAF_HOST)
    assert monitor.get_cert_info()["error"] == "CertificateError"


def test_offline_monitor_never_touches_the_network(bundle, monkeypatch):
    import socket

    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", boom)
    with CertMonitor.from_file(
        bundle, host=LEAF_HOST, enabled_validators=list(VALIDATORS)
    ) as monitor:
        monitor.validate()
        monitor.refresh()
        monitor.validate()


def test_undecodable_certificate_is_reported(bundle, monkeypatch):
    monitor = CertMonitor.from_file(bundle, host=LEAF_HOST)
    monkeypatch.setattr(monitor, "_parse_pem_cert", lambda pem: {})
    info = monitor.get_cert_info()
    assert info["error"] == "CertificateError"
    assert "not a PEM or DER" in info["message"]


def test_probe_is_unsupported_offline(bundle):
    monitor = CertMonitor.from_file(bundle, host=LEAF_HOST)
    probe = monitor._fetch_tls_probe()
    assert probe["result"] == "n/a"
    assert probe["protocol"] == "offline"
    assert "live connection" in probe["reason"]
