"""Offline regressions for the repository review's validation findings."""

import contextlib
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import pytest

from certmonitor import CertMonitor
from certmonitor.validators.hostname import HostnameValidator
from certmonitor.validators.subject_alt_names import SubjectAltNamesValidator


@pytest.mark.parametrize(
    "identity,sans,valid",
    [
        ("example.com", {"DNS": "notexample.com"}, False),
        ("API.EXAMPLE.COM", {"DNS": "*.example.com"}, True),
        ("a.b.example.com", {"DNS": "*.example.com"}, False),
        ("example.com", {"DNS": "*.example.com"}, False),
        ("192.0.2.1", {"IP Address": "192.0.2.1"}, True),
        ("192.0.2.1", {"DNS": "192.0.2.1"}, False),
        ("2001:db8::1", {"IP Address": ["bad", "2001:0db8:0:0:0:0:0:1"]}, True),
        ("example.com", {"DNS": "other.example.com"}, False),
    ],
)
def test_shared_identity_matching(identity, sans, valid):
    cert = {"cert_info": {"subject": {"commonName": identity}, "subjectAltName": sans}}
    assert HostnameValidator().validate(cert, identity, 443)["is_valid"] is valid
    assert (
        SubjectAltNamesValidator().validate(
            cert, "unrelated.primary", 443, alternate_names=[identity]
        )["is_valid"]
        is valid
    )


def test_single_san_count_and_normalization():
    monitor = CertMonitor("example.com")
    info = monitor._to_structured_dict({"subjectAltName": (("DNS", "notexample.com"),)})
    assert info["subjectAltName"]["DNS"] == ["notexample.com"]
    result = SubjectAltNamesValidator().validate(
        {"cert_info": info}, "example.com", 443, alternate_names=["example.com"]
    )
    assert result["count"] == 1
    assert result["is_valid"] is False


def test_false_connection_check_clears_cache_and_reconnects(monkeypatch):
    monitor = CertMonitor("example.com")
    handler = MagicMock()
    handler.check_connection.return_value = False
    monitor.handler, monitor.connected = handler, True
    monitor.cert_data = {"old": True}
    connect = MagicMock(return_value=None)
    monkeypatch.setattr(monitor, "connect", connect)
    assert monitor._ensure_connection() is None
    handler.close.assert_called_once()
    connect.assert_called_once()
    assert monitor.cert_data == {}


@contextlib.contextmanager
def tls_server(pki, require_client=False):
    contexts = []
    for name in ("one", "two"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pki / f"{name}.pem", pki / f"{name}.key")
        if require_client:
            context.load_verify_locations(pki / "ca.pem")
            context.verify_mode = ssl.CERT_REQUIRED
        contexts.append(context)
    current = [0]
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    connections = []
    workers = []

    def handle(raw, context):
        try:
            raw.settimeout(2)
            secure = context.wrap_socket(raw, server_side=True)
            connections.append(secure)
            stop.wait(10)
            secure.close()
        except (OSError, ssl.SSLError):
            raw.close()

    def serve():
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            worker = threading.Thread(target=handle, args=(raw, contexts[current[0]]))
            workers.append(worker)
            worker.start()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield listener.getsockname()[1], current
    finally:
        stop.set()
        listener.close()
        for secure in connections:
            secure.close()
        thread.join(3)
        for worker in workers:
            worker.join(3)


def test_untrusted_ca_and_wrong_identity_fail_independently(local_pki):
    with tls_server(local_pki) as (port, _):
        with CertMonitor(
            "wrong.test", port, connection_host="127.0.0.1", timeout=2
        ) as monitor:
            result = monitor.validate()  # No get_cert_info prerequisite
            assert result["root_certificate"]["status"] == "fail"
            assert result["hostname"]["status"] == "fail"
            assert monitor.cert_data["snapshot_at"]
            assert monitor.der
        assert monitor.connected is False
        assert monitor.cert_data["snapshot_at"]  # Available after context exit.


def test_custom_ca_without_ocsp_and_separate_identity(local_pki):
    with tls_server(local_pki) as (port, _):
        with CertMonitor(
            "wrong.test",
            port,
            connection_host="127.0.0.1",
            server_hostname="localhost",
            cafile=str(local_pki / "ca.pem"),
            timeout=2,
        ) as monitor:
            result = monitor.validate({"hostname": {"expected_identity": "localhost"}})
            assert result["root_certificate"]["status"] == "pass", result
            assert result["hostname"]["is_valid"] is True
            assert result["hostname"]["matched_name"] == "localhost"
            assert monitor.validate()["hostname"]["is_valid"] is False
            assert result["root_certificate"]["revocation_status"] == "not_checked"
            assert "OCSP" not in monitor.cert_info


def test_rotation_requires_refresh_and_never_mixes_trust(local_pki):
    with tls_server(local_pki) as (port, current):
        with CertMonitor(
            "localhost",
            port,
            connection_host="127.0.0.1",
            cafile=str(local_pki / "ca.pem"),
            timeout=2,
        ) as monitor:
            assert monitor.validate()["root_certificate"]["is_valid"]
            original_der, original_time = monitor.der, monitor.snapshot_at
            current[0] = 1
            with patch.object(monitor, "_verify_trust_now") as verify:
                cached = monitor.validate()["root_certificate"]
            verify.assert_not_called()  # same snapshot, same verdict, no handshake
            assert cached["is_valid"]
            monitor.refresh()
            assert monitor.der != original_der
            assert monitor.snapshot_at != original_time
            assert monitor.validate()["root_certificate"]["is_valid"]  # verified anew


def test_client_certificate(local_pki):
    with tls_server(local_pki, require_client=True) as (port, _):
        with CertMonitor(
            "localhost",
            port,
            connection_host="127.0.0.1",
            cafile=str(local_pki / "ca.pem"),
            client_cert=str(local_pki / "one.pem"),
            client_key=str(local_pki / "one.key"),
            timeout=2,
        ) as monitor:
            assert monitor.validate()["root_certificate"]["is_valid"]


@pytest.mark.parametrize("reply", [b"\x15\x03\x03\x00\x02\x02\x28", b"garbage"])
def test_native_probe_malformed_or_alert_is_inconclusive(reply):
    from certmonitor import certinfo

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    port = listener.getsockname()[1]

    def serve():
        with listener:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                connection.recv(8192)
                connection.sendall(reply)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        result = certinfo.probe_tls_handshake("127.0.0.1", port, 1000)
        assert result["result"] == "error"
    finally:
        thread.join(3)


def test_chain_non_ca_is_rejected_and_weak_policy_configurable():
    from certmonitor.validators.chain import ChainValidator
    from certmonitor import certinfo

    # Use a local fixture's shape, updating dates so this checks structural policy.
    from pathlib import Path
    import time

    analysis = certinfo.analyze_chain(
        [
            (Path(__file__).parent / "fixtures" / f"chain_{i}.der").read_bytes()
            for i in range(3)
        ]
    )
    for cert in analysis["certs"]:
        cert["not_before_unix"] = int(time.time()) - 100
        cert["not_after_unix"] = int(time.time()) + 10000
    analysis["certs"][1]["is_ca"] = False
    validator = ChainValidator()
    result = validator.validate({"chain_analysis": analysis}, "example.com", 443)
    assert result["structural_valid"] is False
    assert result["trust_verified"] is False
    analysis["certs"][1]["is_ca"] = True
    analysis["certs"][1]["signature_algorithm_oid"] = "1.2.840.113549.1.1.5"
    assert not validator.validate({"chain_analysis": analysis}, "example.com", 443)[
        "is_valid"
    ]
    assert validator.validate(
        {"chain_analysis": analysis}, "example.com", 443, reject_weak_signatures=False
    )["is_valid"]
