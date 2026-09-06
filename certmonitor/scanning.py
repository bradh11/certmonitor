"""Bounded multi-endpoint scanning using independent monitor instances."""

from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from .core import CertMonitor


Endpoint = str | tuple[str, int] | dict[str, Any]

# CertMonitor keyword options an endpoint dict may carry, besides host and port.
ENDPOINT_OPTIONS = frozenset(
    {
        "connection_host",
        "server_hostname",
        "timeout",
        "cafile",
        "capath",
        "client_cert",
        "client_key",
        "starttls",
    }
)


def scan_hosts(
    hosts: Iterable[Endpoint],
    *,
    port: int = 443,
    max_workers: int = 8,
    timeout: float = 10,
    enabled_validators: list[str] | None = None,
    validator_args: dict[str, Any] | None = None,
    cafile: str | None = None,
    capath: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    starttls: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield completed scans with at most `max_workers` endpoints in flight.

    Each result is a dict with `host`, `port`, `results` (the `validate()`
    output), `snapshot_at`, and `fingerprint_sha256` of the collected leaf. If a scan raises, the dict carries an
    `error` (exception class name) and `message` instead of aborting the
    whole scan, so one bad host never hides the rest. Results arrive in
    completion order. Stopping iteration early returns promptly; scans that
    were still queued are cancelled and in-flight ones finish in the
    background.

    `timeout` bounds individual network operations; platform DNS resolution
    is not interruptible.

    Args:
        hosts: Endpoints to scan, consumed lazily. Each entry is a host name or
            IP address, a `(host, port)` pair, or a dict with `host` plus any of
            `port`, `connection_host`, `server_hostname`, `timeout`, `cafile`,
            `capath`, `client_cert`, `client_key`, and `starttls` for endpoints that need
            their own connection settings.
        port: TCP port for entries that do not carry one. Defaults to 443.
        max_workers: Maximum number of concurrent scans. Defaults to 8.
        timeout: Per-operation network timeout in seconds. Defaults to 10.
        enabled_validators: Validator names to run; `None` uses the defaults.
        validator_args: Per-validator keyword arguments applied to every host,
            in the same shape `validate()` accepts.
        cafile: PEM CA bundle for trust verification on every endpoint. An
            endpoint dict may override it.
        capath: CA directory for trust verification on every endpoint.
        client_cert: Client certificate for mutual TLS on every endpoint.
        client_key: Client private key, if separate from `client_cert`.
        starttls: STARTTLS protocol name applied to every endpoint (`"smtp"`,
            `"imap"`, `"pop3"`, `"ftp"`, `"postgres"`, `"ldap"`); endpoint
            dicts may set their own.

    Raises:
        ValueError: If `max_workers` or `timeout` is not positive.

    Example:
        ```python
        from certmonitor import scan_hosts

        targets = [
            "example.com",
            ("legacy.example.net", 8443),
            {"host": "api.example.com", "connection_host": "192.0.2.10"},
        ]
        for scan in scan_hosts(targets, max_workers=4, cafile="/path/to/private-ca.pem"):
            print(scan["host"], scan["port"], scan["results"]["expiration"]["status"])
        ```
    """
    if max_workers < 1 or timeout <= 0:
        raise ValueError("max_workers and timeout must be positive")
    endpoints = iter(hosts)

    shared = {
        "timeout": timeout,
        "cafile": cafile,
        "capath": capath,
        "client_cert": client_cert,
        "client_key": client_key,
        "starttls": starttls,
    }

    def describe(entry: Endpoint) -> tuple[str, int, dict[str, Any]]:
        if isinstance(entry, str):
            return entry, port, {}
        if isinstance(entry, dict):
            unknown = set(entry) - ENDPOINT_OPTIONS - {"host", "port"}
            if "host" not in entry or unknown:
                raise ValueError(
                    f"endpoint dict needs 'host' and may only set {sorted(ENDPOINT_OPTIONS)}"
                )
            options = {k: v for k, v in entry.items() if k in ENDPOINT_OPTIONS}
            return str(entry["host"]), int(entry.get("port", port)), options
        host, entry_port = entry
        return host, entry_port, {}

    def scan(entry: Endpoint) -> dict[str, Any]:
        host, entry_port = (entry if isinstance(entry, str) else str(entry)), port
        try:
            host, entry_port, options = describe(entry)
            with CertMonitor(
                host, entry_port, enabled_validators, **{**shared, **options}
            ) as monitor:
                report = {
                    "host": host,
                    "port": entry_port,
                    "results": monitor.validate(validator_args),
                    "snapshot_at": monitor.snapshot_at,
                    "fingerprint_sha256": monitor.fingerprint_sha256,
                }
                if monitor.connection_host != host:
                    report["connection_host"] = monitor.connection_host
                return report
        except Exception as exc:  # noqa: BLE001
            return {
                "host": host,
                "port": entry_port,
                "results": {},
                "snapshot_at": None,
                "error": type(exc).__name__,
                "message": str(exc),
            }

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        pending = set()
        for _ in range(max_workers):
            host = next(endpoints, None)
            if host is None:
                break
            pending.add(executor.submit(scan, host))
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield future.result()
                host = next(endpoints, None)
                if host is not None:
                    pending.add(executor.submit(scan, host))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
