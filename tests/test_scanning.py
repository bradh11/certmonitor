"""Behavior of the bounded multi-host scanner."""

import threading
import time
from unittest.mock import MagicMock

import certmonitor.scanning as scanning
from certmonitor.scanning import scan_hosts


def passing_hostname(*args, **kwargs):
    return {"hostname": {"is_valid": True}}


def passing_expiration(*args, **kwargs):
    return {"expiration": {"is_valid": True}}


def no_results(*args, **kwargs):
    return {}


def _fake_monitor(monkeypatch, validate):
    mock = MagicMock()
    mock.return_value.__enter__.return_value.validate.side_effect = validate
    mock.return_value.__enter__.return_value.snapshot_at = "2026-09-05T00:00:00+00:00"
    monkeypatch.setattr(scanning, "CertMonitor", mock)
    return mock


def test_bounds_input_consumption(monkeypatch):
    consumed = []

    def hosts():
        for index in range(20):
            consumed.append(index)
            yield f"host{index}"

    _fake_monitor(monkeypatch, passing_hostname)
    results = scan_hosts(hosts(), max_workers=3)
    next(results)
    assert len(consumed) == 3
    assert len(list(results)) == 19


def test_one_failing_host_does_not_abort_the_scan(monkeypatch):
    mock = _fake_monitor(monkeypatch, passing_hostname)

    def enter(*args, **kwargs):
        monitor = MagicMock()
        if mock.call_args_list[-1].args[0] == "bad.test":
            monitor.validate.side_effect = RuntimeError("validator exploded")
        else:
            monitor.validate.return_value = {"hostname": {"is_valid": True}}
        return monitor

    mock.return_value.__enter__.side_effect = enter
    results = {r["host"]: r for r in scan_hosts(["ok.test", "bad.test", "also.test"])}
    assert set(results) == {"ok.test", "bad.test", "also.test"}
    assert results["bad.test"]["error"] == "RuntimeError"
    assert results["bad.test"]["message"] == "validator exploded"
    assert results["ok.test"]["results"]["hostname"]["is_valid"] is True


def test_breaking_early_returns_promptly(monkeypatch):
    release = threading.Event()

    def slow_validate():
        release.wait(5)
        return {}

    _fake_monitor(monkeypatch, slow_validate)
    scans = scan_hosts([f"host{i}" for i in range(10)], max_workers=4)
    started = time.monotonic()
    release.set()
    next(scans)
    release.clear()
    scans.close()
    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 2


def test_rejects_non_positive_limits():
    import pytest

    with pytest.raises(ValueError):
        next(scan_hosts(["a"], max_workers=0))
    with pytest.raises(ValueError):
        next(scan_hosts(["a"], timeout=0))


def test_host_port_pairs_and_validator_args(monkeypatch):
    mock = _fake_monitor(monkeypatch, passing_expiration)
    results = {
        (r["host"], r["port"]): r
        for r in scan_hosts(
            ["a.test", ("b.test", 8443)],
            port=443,
            validator_args={"expiration": {"warning_days": 30}},
        )
    }
    assert set(results) == {("a.test", 443), ("b.test", 8443)}
    constructed = {(c.args[0], c.args[1]) for c in mock.call_args_list}
    assert constructed == {("a.test", 443), ("b.test", 8443)}
    validate = mock.return_value.__enter__.return_value.validate
    assert validate.call_args.args == ({"expiration": {"warning_days": 30}},)


def test_endpoint_dicts_and_shared_options(monkeypatch):
    mock = _fake_monitor(monkeypatch, passing_expiration)
    mock.return_value.__enter__.return_value.connection_host = "192.0.2.10"
    results = list(
        scan_hosts(
            [{"host": "api.test", "connection_host": "192.0.2.10", "timeout": 2}],
            cafile="ca.pem",
            client_cert="client.pem",
        )
    )
    kwargs = mock.call_args.kwargs
    assert mock.call_args.args[:2] == ("api.test", 443)
    assert kwargs["connection_host"] == "192.0.2.10"
    assert kwargs["timeout"] == 2  # endpoint overrides the scan-level default
    assert kwargs["cafile"] == "ca.pem" and kwargs["client_cert"] == "client.pem"
    assert results[0]["connection_host"] == "192.0.2.10"


def test_invalid_endpoint_dict_is_a_per_entry_error(monkeypatch):
    _fake_monitor(monkeypatch, no_results)
    results = list(
        scan_hosts([{"port": 443}, {"host": "x.test", "bogus": 1}, "ok.test"])
    )
    errors = [r for r in results if "error" in r]
    assert len(errors) == 2 and all(r["error"] == "ValueError" for r in errors)
    assert [r["host"] for r in results if "error" not in r] == ["ok.test"]
