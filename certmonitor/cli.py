"""Command-line interface: `certmonitor check`, `info`, and `validators`.

Built on `argparse` and `json` only, so the command ships with the package
and adds no dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .core import CertMonitor

STATUS_LABELS = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "error": "ERROR",
    "unsupported": "N/A",
}
FAILING = {"fail", "error"}


def _version() -> str:
    try:
        return version("certmonitor")
    except PackageNotFoundError:  # running from a source checkout
        return "unknown"


def parse_target(target: str) -> tuple[str, int | None]:
    """Split `host`, `host:port`, `[v6]:port`, or a bare IPv6 address."""
    if target.startswith("["):
        host, closed, rest = target[1:].partition("]")
        if not closed:
            raise argparse.ArgumentTypeError(f"unterminated IPv6 literal: {target}")
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise argparse.ArgumentTypeError(f"expected [host]:port, got {target}")
        return host, _port(rest[1:], target)
    if target.count(":") == 1:
        host, port_text = target.split(":")
        return host, _port(port_text, target)
    return target, None  # plain host or bare IPv6


def _port(text: str, target: str) -> int:
    if not text.isdigit() or not 0 < int(text) < 65536:
        raise argparse.ArgumentTypeError(f"invalid port in {target}")
    return int(text)


def parse_validator_arg(text: str) -> tuple[str, str, Any]:
    """Turn `validator.key=value` into a triple; values are JSON when they parse."""
    key, sep, raw = text.partition("=")
    validator, dot, name = key.partition(".")
    if not sep or not dot or not validator or not name:
        raise argparse.ArgumentTypeError(f"expected validator.key=value, got {text!r}")
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    return validator, name, value


def _validator_args(pairs: list[tuple[str, str, Any]]) -> dict[str, Any] | None:
    if not pairs:
        return None
    args: dict[str, dict[str, Any]] = {}
    for validator, name, value in pairs:
        args.setdefault(validator, {})[name] = value
    return args


def _monitor_options(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "timeout": args.timeout,
        "cafile": args.cafile,
        "capath": args.capath,
        "client_cert": args.client_cert,
        "client_key": args.client_key,
        "connection_host": args.connection_host,
        "server_hostname": args.server_hostname,
    }


def _summary(name: str, result: dict[str, Any]) -> str:
    """One short phrase per validator for the human-readable report."""
    if result.get("reason"):
        return str(result["reason"])
    warnings = result.get("warnings") or []
    if warnings and result.get("status") == "warn":
        return str(warnings[0])
    detail = {
        "expiration": lambda r: f"{r.get('days_to_expiry')} days remaining",
        "hostname": lambda r: f"matched {r.get('matched_name')}",
        "subject_alt_names": lambda r: f"{r.get('count')} SANs",
        "root_certificate": lambda r: "trust verified",
        "tls_version": lambda r: str(r.get("protocol_version")),
        "weak_cipher": lambda r: str(r.get("cipher_suite")),
        "key_info": lambda r: f"{r.get('key_type')} {r.get('key_size')}",
        "chain": lambda r: f"{r.get('chain_length')} certificates",
        "pq_key_exchange": lambda r: str(r.get("kem_name")),
        "pq_signature": lambda r: str(r.get("key_algorithm")),
    }.get(name)
    return detail(result) if detail else ""


def _run_check_job(job: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    validators = args.validators
    try:
        if job["kind"] == "file":
            monitor = CertMonitor.from_file(
                job["path"],
                host=args.host,
                port=args.port,
                enabled_validators=validators,
            )
        else:
            monitor = CertMonitor(
                job["host"], job["port"], validators, **_monitor_options(args)
            )
        with monitor as active:
            results = active.validate(_validator_args(args.arg))
            return {
                "target": job["label"],
                "results": results,
                "snapshot_at": active.snapshot_at,
            }
    except Exception as exc:  # noqa: BLE001  (one bad target must not stop the run)
        return {
            "target": job["label"],
            "results": {},
            "snapshot_at": None,
            "error": type(exc).__name__,
            "message": str(exc),
        }


def _check_jobs(args: argparse.Namespace) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for host, port in args.targets:
        port = port or args.port
        label = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        jobs.append({"kind": "live", "host": host, "port": port, "label": label})
    for path in args.file:
        jobs.append({"kind": "file", "path": path, "label": path})
    return jobs


def _print_report(reports: list[dict[str, Any]], out: Any) -> None:
    for report in reports:
        print(report["target"], file=out)
        if "error" in report:
            print(f"  ERROR  {report['error']}: {report['message']}", file=out)
            continue
        for name, result in report["results"].items():
            label = STATUS_LABELS.get(result.get("status", ""), "?")
            print(f"  {label:<5}  {name:<18} {_summary(name, result)}", file=out)


def _exit_code(reports: list[dict[str, Any]], fail_on_warn: bool) -> int:
    bad = set(FAILING) | ({"warn"} if fail_on_warn else set())
    for report in reports:
        if "error" in report:
            return 1
        if any(r.get("status") in bad for r in report["results"].values()):
            return 1
    return 0


def cmd_check(args: argparse.Namespace, out: Any) -> int:
    jobs = _check_jobs(args)
    if not jobs:
        print("check: give at least one target or --file", file=sys.stderr)
        return 2
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(jobs)))) as pool:
        reports = list(pool.map(lambda job: _run_check_job(job, args), jobs))
    if args.json:
        json.dump(reports, out, indent=2)
        print(file=out)
    else:
        _print_report(reports, out)
    return _exit_code(reports, args.fail_on_warn)


def cmd_info(args: argparse.Namespace, out: Any) -> int:
    if args.file:
        monitor = CertMonitor.from_file(args.file, host=args.host, port=args.port)
    else:
        host, port = args.target
        monitor = CertMonitor(host, port or args.port, [], **_monitor_options(args))
    with monitor as active:
        payload: Any = active.get_raw_pem() if args.pem else active.get_cert_info()
    if isinstance(payload, dict) and "error" in payload:
        print(f"{payload['error']}: {payload.get('message', '')}", file=sys.stderr)
        return 1
    if args.pem:
        out.write(str(payload))
    else:
        json.dump(payload, out, indent=2, default=str)
        print(file=out)
    return 0


def cmd_validators(args: argparse.Namespace, out: Any) -> int:
    described = CertMonitor("localhost", enabled_validators=[]).describe_validators()
    if args.json:
        json.dump(described, out, indent=2, default=str)
        print(file=out)
        return 0
    for name, info in described.items():
        print(f"{name}: {info.get('doc') or ''}".rstrip(": "), file=out)
        for arg, spec in info.get("args", {}).items():
            print(
                f"    --arg {name}.{arg}=<{spec['annotation']}>  (default {spec['default']!r})",
                file=out,
            )
    return 0


def _add_connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--port", type=int, default=443, help="default port (443)")
    parser.add_argument(
        "--timeout", type=float, default=10, help="seconds per network operation (10)"
    )
    parser.add_argument("--cafile", help="PEM CA bundle for trust verification")
    parser.add_argument("--capath", help="CA directory for trust verification")
    parser.add_argument("--client-cert", help="client certificate for mutual TLS")
    parser.add_argument("--client-key", help="client private key, if separate")
    parser.add_argument(
        "--connection-host", help="connect to this address instead of the target host"
    )
    parser.add_argument(
        "--server-hostname", help="SNI name to send instead of the target host"
    )
    parser.add_argument("--host", help="identity to check for --file targets")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certmonitor",
        description="Check TLS certificates from the command line.",
    )
    parser.add_argument(
        "--version", action="version", version=f"certmonitor {_version()}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser(
        "check",
        help="run the validators against hosts or certificate files",
        description="Validate one or more targets. Targets are host, host:port, or [ipv6]:port.",
    )
    check.add_argument("targets", nargs="*", type=parse_target, metavar="TARGET")
    check.add_argument(
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="PEM or DER file to check (repeatable)",
    )
    check.add_argument(
        "-v",
        "--validators",
        type=lambda s: s.split(","),
        help="comma-separated validator names (default set if omitted)",
    )
    check.add_argument(
        "--arg",
        action="append",
        default=[],
        type=parse_validator_arg,
        metavar="VALIDATOR.KEY=VALUE",
        help="validator argument; VALUE is parsed as JSON when possible (repeatable)",
    )
    check.add_argument("--workers", type=int, default=8, help="concurrent targets (8)")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.add_argument(
        "--fail-on-warn", action="store_true", help="exit 1 on warnings too"
    )
    _add_connection_options(check)
    check.set_defaults(func=cmd_check)

    info = commands.add_parser(
        "info",
        help="print the parsed certificate",
        description="Print the parsed certificate for one target, or its PEM.",
    )
    info.add_argument("target", nargs="?", type=parse_target, metavar="TARGET")
    info.add_argument(
        "--file", metavar="PATH", help="PEM or DER file instead of a host"
    )
    info.add_argument(
        "--pem", action="store_true", help="print the PEM instead of parsed fields"
    )
    _add_connection_options(info)
    info.set_defaults(func=cmd_info)

    validators = commands.add_parser(
        "validators", help="list validators and their arguments"
    )
    validators.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    validators.set_defaults(func=cmd_validators)
    return parser


def main(argv: Sequence[str] | None = None, out: Any = None) -> int:
    """Entry point for the `certmonitor` command. Returns the exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "info" and not args.target and not args.file:
        parser.error("info: give a TARGET or --file")
    return int(args.func(args, out or sys.stdout))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
