"""Behavior of the bounded multi-host scanner."""

import threading
import time
from unittest.mock import MagicMock

import certmonitor.scanning as scanning
from certmonitor.scanning import scan_hosts


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

    _fake_monitor(monkeypatch, lambda: {"hostname": {"is_valid": True}})
    results = scan_hosts(hosts(), max_workers=3)
    next(results)
    assert len(consumed) == 3
    assert len(list(results)) == 19


def test_one_failing_host_does_not_abort_the_scan(monkeypatch):
    mock = _fake_monitor(monkeypatch, lambda: {"hostname": {"is_valid": True}})

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
