"""The certmonitor command: argument parsing, reports, and exit codes."""

import io
import json
import ssl
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import certmonitor.cli as cli
from certmonitor.cli import main, parse_target, parse_validator_arg

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHAIN_DER = [(FIXTURES / f"chain_{i}.der").read_bytes() for i in range(3)]
LEAF_HOST = "www.google.com"


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "chain.pem"
    path.write_text("".join(ssl.DER_cert_to_PEM_cert(der) for der in CHAIN_DER))
    return str(path)


def run(argv):
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


@pytest.mark.parametrize(
    "target,expected",
    [
        ("example.com", ("example.com", None)),
        ("example.com:8443", ("example.com", 8443)),
        ("[2001:db8::1]:1010", ("2001:db8::1", 1010)),
        ("[2001:db8::1]", ("2001:db8::1", None)),
        ("2001:db8::1", ("2001:db8::1", None)),
    ],
)
def test_parse_target(target, expected):
    assert parse_target(target) == expected


@pytest.mark.parametrize(
    "target", ["example.com:abc", "example.com:0", "[2001:db8::1", "[::1]x"]
)
def test_parse_target_rejects_bad_input(target):
    with pytest.raises(Exception):
        parse_target(target)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("expiration.warning_days=30", ("expiration", "warning_days", 30)),
        (
            "expiration.max_lifetime_days=null",
            ("expiration", "max_lifetime_days", None),
        ),
        (
            'subject_alt_names.alternate_names=["a.test","b.test"]',
            ("subject_alt_names", "alternate_names", ["a.test", "b.test"]),
        ),
        (
            "hostname.expected_identity=api.example.com",
            ("hostname", "expected_identity", "api.example.com"),
        ),
    ],
)
def test_parse_validator_arg(text, expected):
    assert parse_validator_arg(text) == expected


def test_validator_arg_requires_dotted_key():
    with pytest.raises(Exception):
        parse_validator_arg("warning_days=30")


def test_check_file_reports_each_validator(bundle):
    code, out = run(
        [
            "check",
            "--file",
            bundle,
            "--host",
            LEAF_HOST,
            "-v",
            "hostname,key_info,tls_version",
        ]
    )
    assert code == 0
    assert out.splitlines()[0].startswith(bundle + "  sha256:")
    assert "PASS   hostname" in out and f"matched {LEAF_HOST}" in out
    assert "PASS   key_info" in out
    assert "N/A    tls_version" in out and "live connection" in out


def test_check_exit_code_reflects_failures(bundle):
    code, out = run(
        ["check", "--file", bundle, "--host", LEAF_HOST, "-v", "expiration"]
    )
    assert code == 1  # the fixture leaf has expired
    assert "FAIL   expiration" in out


def test_fail_on_warn(bundle):
    ok, _ = run(
        [
            "check",
            "--file",
            bundle,
            "--host",
            LEAF_HOST,
            "-v",
            "chain",
            "--arg",
            "chain.reject_weak_signatures=false",
        ]
    )
    strict, _ = run(
        [
            "check",
            "--file",
            bundle,
            "--host",
            LEAF_HOST,
            "-v",
            "chain",
            "--arg",
            "chain.reject_weak_signatures=false",
            "--fail-on-warn",
        ]
    )
    assert strict >= ok


def test_check_json_output(bundle):
    code, out = run(
        ["check", "--file", bundle, "--host", LEAF_HOST, "-v", "key_info", "--json"]
    )
    assert code == 0
    report = json.loads(out)
    assert report[0]["target"] == bundle
    assert report[0]["results"]["key_info"]["status"] == "pass"
    assert report[0]["snapshot_at"]
    assert len(report[0]["fingerprint_sha256"]) == 64


def test_check_missing_file_is_an_error_line(tmp_path):
    code, out = run(["check", "--file", str(tmp_path / "nope.pem"), "-v", "key_info"])
    assert code == 1
    assert "ERROR" in out
    # The report keeps the file error rather than tripping over its own fields.
    assert "AttributeError" not in out
    assert "CertificateError" in out or "No such file" in out


def test_misspelled_validator_fails_the_run(bundle):
    code, out = run(
        ["check", "--file", bundle, "--host", LEAF_HOST, "-v", "hostname,expiraton"]
    )
    assert code == 1
    assert "ERROR  expiraton" in out and "not implemented" in out


def test_check_requires_a_target(capsys):
    assert main(["check"]) == 2


def test_check_live_targets_use_host_port_and_options(monkeypatch):
    fake = MagicMock()
    monitor = fake.return_value.__enter__.return_value
    monitor.validate.return_value = {
        "expiration": {"is_valid": True, "status": "pass", "days_to_expiry": 5}
    }
    monitor.snapshot_at = "now"
    monkeypatch.setattr(cli, "CertMonitor", fake)
    code, out = run(
        [
            "check",
            "a.test",
            "b.test:8443",
            "--arg",
            "expiration.warning_days=30",
            "--timeout",
            "3",
            "--cafile",
            "ca.pem",
            "--workers",
            "1",
        ]
    )
    assert code == 0
    assert "a.test:443" in out and "b.test:8443" in out and "5 days remaining" in out
    calls = {(c.args[0], c.args[1]) for c in fake.call_args_list}
    assert calls == {("a.test", 443), ("b.test", 8443)}
    assert (
        fake.call_args.kwargs["timeout"] == 3
        and fake.call_args.kwargs["cafile"] == "ca.pem"
    )
    assert monitor.validate.call_args.args == ({"expiration": {"warning_days": 30}},)


def test_check_one_raising_target_does_not_stop_the_run(monkeypatch):
    def construct(host, port, *args, **kwargs):
        # Targets run in worker threads, so decide per host here rather than
        # from whichever call happened to be recorded last.
        fake = MagicMock()
        monitor = fake.__enter__.return_value
        if host == "bad.test":
            monitor.validate.side_effect = RuntimeError("boom")
        else:
            monitor.validate.return_value = {
                "hostname": {
                    "is_valid": True,
                    "status": "pass",
                    "matched_name": "ok.test",
                }
            }
        monitor.snapshot_at = "now"
        monitor.fingerprint_sha256 = None
        monitor.cert_info = {}
        monitor.public_key_info = None
        return fake

    monkeypatch.setattr(cli, "CertMonitor", MagicMock(side_effect=construct))
    code, out = run(["check", "ok.test", "bad.test", "--json"])
    assert code == 1
    report = {r["target"]: r for r in json.loads(out)}
    assert report["bad.test:443"]["error"] == "RuntimeError"
    assert report["ok.test:443"]["results"]["hostname"]["status"] == "pass"


def test_info_file_prints_parsed_certificate(bundle):
    code, out = run(["info", "--file", bundle])
    assert code == 0
    assert json.loads(out)["subject"]["commonName"] == LEAF_HOST


def test_info_pem(bundle):
    code, out = run(["info", "--file", bundle, "--pem"])
    assert code == 0
    assert out.startswith("-----BEGIN CERTIFICATE-----")


def test_info_requires_a_target():
    with pytest.raises(SystemExit):
        main(["info"])


def test_info_error_exits_one(tmp_path):
    code, _ = run(["info", "--file", str(tmp_path / "nope.pem")])
    assert code == 1


def test_validators_lists_arguments():
    code, out = run(["validators"])
    assert code == 0
    assert "expiration:" in out
    assert "--arg expiration.warning_days=<float>  (default 7)" in out
    code, out = run(["validators", "--json"])
    assert json.loads(out)["hostname"]["args"]["expected_identity"]["default"] is None


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.startswith("certmonitor ")


def test_version_falls_back_outside_an_installed_package(monkeypatch):
    from importlib.metadata import PackageNotFoundError

    def missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.setattr(cli, "version", missing)
    assert cli._version() == "unknown"


def test_warning_becomes_the_summary():
    result = {"is_valid": True, "status": "warn", "warnings": ["expires soon"]}
    assert cli._summary("expiration", result) == "expires soon"


def test_human_report_shows_target_errors(monkeypatch):
    fake = MagicMock()
    fake.return_value.__enter__.side_effect = OSError("network down")
    monkeypatch.setattr(cli, "CertMonitor", fake)
    code, out = run(["check", "down.test"])
    assert code == 1
    assert "down.test:443" in out
    assert "ERROR  OSError: network down" in out


def test_info_live_target_uses_connection_options(monkeypatch):
    fake = MagicMock()
    fake.return_value.__enter__.return_value.get_cert_info.return_value = {
        "subject": {"commonName": "a.test"}
    }
    monkeypatch.setattr(cli, "CertMonitor", fake)
    code, out = run(
        ["info", "a.test:8443", "--timeout", "2", "--server-hostname", "sni.test"]
    )
    assert code == 0
    assert json.loads(out)["subject"]["commonName"] == "a.test"
    assert fake.call_args.args[:2] == ("a.test", 8443)
    assert fake.call_args.kwargs["timeout"] == 2
    assert fake.call_args.kwargs["server_hostname"] == "sni.test"


def test_summary_renders_missing_fields_as_question_marks():
    assert (
        cli._summary("expiration", {"is_valid": True, "status": "pass"})
        == "? days remaining"
    )
    assert cli._summary("unknown_validator", {"is_valid": True}) == ""
