"""compare_snapshots() explains what changed between two observations."""

import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from certmonitor import compare_snapshots
from certmonitor.cli import main

FORMAT = "%b %d %H:%M:%S %Y GMT"


def stamp(days):
    return (datetime(2026, 9, 1, tzinfo=timezone.utc) + timedelta(days=days)).strftime(
        FORMAT
    )


def snapshot(**overrides):
    certificate = {
        "subject": {"commonName": "api.example.com"},
        "issuer": {
            "organizationName": "Example CA",
            "commonName": "Example Issuing CA 1",
        },
        "serialNumber": "01",
        "notBefore": stamp(0),
        "notAfter": stamp(90),
        "subjectAltName": {
            "DNS": ["api.example.com", "www.example.com"],
            "IP Address": [],
        },
        "fingerprint_sha256": "aa" * 32,
    }
    certificate.update(overrides.pop("certificate", {}))
    report = {
        "target": "api.example.com:443",
        "results": {
            "expiration": {"status": "pass"},
            "hostname": {"status": "pass"},
            "root_certificate": {"status": "pass"},
            "key_info": {"status": "pass", "key_type": "ecPublicKey", "key_size": 256},
        },
        "snapshot_at": "2026-09-01T00:00:00+00:00",
        "fingerprint_sha256": certificate["fingerprint_sha256"],
        "certificate": certificate,
        "public_key_info": {"algorithm": "ecPublicKey", "size": 256},
    }
    report.update(overrides)
    return report


def test_identical_snapshots_are_unchanged():
    report = compare_snapshots(snapshot(), snapshot())
    assert report == {
        "changed": False,
        "replaced": False,
        "severity": "info",
        "findings": [],
    }


def test_routine_renewal_is_informational():
    renewed = snapshot(
        fingerprint_sha256="bb" * 32,
        certificate={
            "fingerprint_sha256": "bb" * 32,
            "serialNumber": "02",
            "notBefore": stamp(80),
            "notAfter": stamp(170),
        },
    )
    report = compare_snapshots(snapshot(), renewed)
    assert report["replaced"] is True
    assert report["severity"] == "info"
    assert report["validity"]["extended_days"] == 80
    assert any("routine renewal" in f for f in report["findings"])


def test_removed_san_is_a_warning():
    changed = snapshot(
        certificate={"subjectAltName": {"DNS": ["www.example.com"], "IP Address": []}}
    )
    report = compare_snapshots(snapshot(), changed)
    assert report["severity"] == "warning"
    assert report["sans"] == {"added": [], "removed": ["DNS:api.example.com"]}
    assert "Names removed from the SANs: DNS:api.example.com." in report["findings"]


def test_added_san_is_a_notice():
    changed = snapshot(
        certificate={
            "subjectAltName": {
                "DNS": ["api.example.com", "www.example.com", "new.example.com"],
                "IP Address": [],
            }
        }
    )
    report = compare_snapshots(snapshot(), changed)
    assert report["severity"] == "notice"
    assert report["sans"]["added"] == ["DNS:new.example.com"]


def test_issuer_change_is_a_warning():
    changed = snapshot(
        certificate={
            "issuer": {"organizationName": "Other CA", "commonName": "Other Issuing CA"}
        }
    )
    report = compare_snapshots(snapshot(), changed)
    assert report["severity"] == "warning"
    assert (
        "Issuer changed from Example Issuing CA 1 to Other Issuing CA."
        in report["findings"]
    )


def test_weaker_key_is_a_warning_and_stronger_key_a_notice():
    weaker = snapshot(public_key_info={"algorithm": "rsaEncryption", "size": 1024})
    stronger = snapshot(public_key_info={"algorithm": "rsaEncryption", "size": 4096})
    assert compare_snapshots(snapshot(), weaker)["severity"] == "warning"
    assert compare_snapshots(snapshot(), stronger)["severity"] == "notice"
    assert compare_snapshots(snapshot(), stronger)["key"]["current"] == {
        "algorithm": "rsaEncryption",
        "size": 4096,
    }


def test_status_regression_is_a_warning():
    failing = snapshot()
    failing["results"]["root_certificate"] = {"status": "fail"}
    report = compare_snapshots(snapshot(), failing)
    assert report["severity"] == "warning"
    assert report["status_changes"] == {
        "root_certificate": {"previous": "pass", "current": "fail"}
    }
    assert "root_certificate went from pass to fail." in report["findings"]


def test_status_recovery_is_a_notice():
    failing = snapshot()
    failing["results"]["expiration"] = {"status": "fail"}
    report = compare_snapshots(failing, snapshot())
    assert report["severity"] == "notice"


def test_shortened_validity_is_a_notice():
    shorter = snapshot(certificate={"notAfter": stamp(30)})
    report = compare_snapshots(snapshot(), shorter)
    assert report["validity"]["extended_days"] == -60
    assert report["severity"] == "notice"


def test_bare_cert_info_dicts_are_accepted():
    before = snapshot()["certificate"]
    after = dict(
        before, serialNumber="02", fingerprint_sha256="cc" * 32, notAfter=stamp(180)
    )
    report = compare_snapshots(before, after)
    assert report["replaced"] is True
    assert report["validity"]["extended_days"] == 90


def test_serial_number_stands_in_when_fingerprints_are_missing():
    before = {"serialNumber": "01", "notAfter": stamp(10)}
    after = {"serialNumber": "02", "notAfter": stamp(10)}
    assert compare_snapshots(before, after)["replaced"] is True
    assert compare_snapshots(before, dict(before))["replaced"] is False


# --- certmonitor diff ------------------------------------------------------------


def run(argv):
    out = io.StringIO()
    return main(argv, out=out), out.getvalue()


def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return str(path)


def test_diff_reports_per_target_and_exit_code(tmp_path):
    before = write(tmp_path, "before.json", [snapshot()])
    after = write(
        tmp_path,
        "after.json",
        [
            snapshot(
                certificate={
                    "subjectAltName": {"DNS": ["www.example.com"], "IP Address": []}
                }
            )
        ],
    )
    code, out = run(["diff", before, after])
    assert code == 1
    assert out.startswith("api.example.com:443  WARNING")
    assert "Names removed from the SANs" in out


def test_diff_same_is_exit_zero(tmp_path):
    before = write(tmp_path, "before.json", [snapshot()])
    after = write(tmp_path, "after.json", [snapshot()])
    code, out = run(["diff", before, after])
    assert code == 0
    assert "SAME" in out


def test_diff_fail_on_notice_and_missing_targets(tmp_path):
    before = write(
        tmp_path,
        "before.json",
        [snapshot(), dict(snapshot(), target="gone.example.com:443")],
    )
    after = write(
        tmp_path,
        "after.json",
        [snapshot(), dict(snapshot(), target="new.example.com:443")],
    )
    code, out = run(["diff", before, after, "--fail-on", "notice", "--json"])
    assert code == 1
    report = json.loads(out)
    assert report["gone.example.com:443"]["findings"] == [
        "Missing from the current run."
    ]
    assert report["new.example.com:443"]["findings"] == [
        "Not present in the previous run."
    ]
    assert report["api.example.com:443"]["changed"] is False


def test_diff_accepts_single_snapshots(tmp_path):
    before = write(tmp_path, "before.json", snapshot()["certificate"])
    after = write(
        tmp_path,
        "after.json",
        dict(snapshot()["certificate"], issuer={"commonName": "Other"}),
    )
    code, out = run(["diff", before, after])
    assert code == 1
    assert "Issuer changed" in out


def test_diff_rejects_unexpected_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('"just a string"')
    with pytest.raises(ValueError):
        main(["diff", str(path), str(path)], out=io.StringIO())


def test_subject_change_is_a_notice():
    changed = snapshot(certificate={"subject": {"commonName": "other.example.com"}})
    report = compare_snapshots(snapshot(), changed)
    assert report["severity"] == "notice"
    assert report["subject"]["current"] == {"commonName": "other.example.com"}
    assert (
        "Subject changed from api.example.com to other.example.com."
        in report["findings"]
    )


def test_unparsable_dates_are_ignored_rather_than_fatal():
    before = {"serialNumber": "01", "notBefore": "yesterday", "notAfter": "not a date"}
    after = {"serialNumber": "01", "notBefore": 12345, "notAfter": None}
    report = compare_snapshots(before, after)
    assert report["changed"] is False
    assert "validity" not in report


def test_names_that_are_not_dicts_are_rendered_verbatim():
    report = compare_snapshots({"issuer": "Old CA"}, {"issuer": "New CA"})
    assert report["findings"] == ["Issuer changed from Old CA to New CA."]


def test_disappearing_and_appearing_checks_are_findings():
    before = snapshot(
        results={"hostname": {"status": "pass"}, "expiration": {"status": "pass"}}
    )
    after = snapshot(
        results={"expiration": {"status": "pass"}, "chain": {"status": "warn"}}
    )
    report = compare_snapshots(before, after)
    assert report["changed"] is True
    assert report["severity"] == "notice"
    assert "hostname is no longer checked (it was pass)." in report["findings"]
    assert "chain is newly checked (warn)." in report["findings"]
    assert report["status_changes"]["hostname"] == {"previous": "pass", "current": None}
    assert report["status_changes"]["chain"] == {"previous": None, "current": "warn"}


def test_errored_scans_are_reported_not_compared():
    good = snapshot()
    failed = {
        "host": "a.test",
        "port": 443,
        "results": {},
        "error": "ConnectionError",
        "message": "refused",
    }
    current_failed = compare_snapshots(good, failed)
    assert current_failed["changed"] is True
    assert current_failed["severity"] == "warning"
    assert current_failed["findings"] == [
        "The current scan failed (ConnectionError: refused); the certificate could not be observed."
    ]
    assert "fingerprint" not in current_failed and "issuer" not in current_failed
    assert current_failed["scan_error"] == {"current": "ConnectionError: refused"}

    previous_failed = compare_snapshots(failed, good)
    assert previous_failed["changed"] is False
    assert previous_failed["severity"] == "notice"
    assert previous_failed["findings"][0].startswith(
        "The previous scan failed (ConnectionError: refused)"
    )

    both = compare_snapshots(failed, {**failed, "message": None})
    assert both["scan_error"] == {
        "previous": "ConnectionError: refused",
        "current": "ConnectionError",
    }
