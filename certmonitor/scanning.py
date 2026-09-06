"""Bounded multi-endpoint scanning using independent monitor instances."""

from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from .core import CertMonitor


def scan_hosts(
    hosts: Iterable[str],
    *,
    port: int = 443,
    max_workers: int = 8,
    timeout: float = 10,
    enabled_validators: list[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield completed scans with at most `max_workers` endpoints in flight.

    Each result is a dict with `host`, `port`, `results` (the `validate()`
    output), and `snapshot_at`. If a scan raises, the dict carries an
    `error` (exception class name) and `message` instead of aborting the
    whole scan, so one bad host never hides the rest. Results arrive in
    completion order. Stopping iteration early returns promptly; scans that
    were still queued are cancelled and in-flight ones finish in the
    background.

    `timeout` bounds individual network operations; platform DNS resolution
    is not interruptible.

    Args:
        hosts: Host names or IP addresses to scan. Consumed lazily.
        port: TCP port to scan on every host. Defaults to 443.
        max_workers: Maximum number of concurrent scans. Defaults to 8.
        timeout: Per-operation network timeout in seconds. Defaults to 10.
        enabled_validators: Validator names to run; `None` uses the defaults.

    Raises:
        ValueError: If `max_workers` or `timeout` is not positive.

    Example:
        ```python
        from certmonitor import scan_hosts

        for scan in scan_hosts(["example.com", "example.org"], max_workers=4):
            print(scan["host"], scan["results"]["expiration"]["status"])
        ```
    """
    if max_workers < 1 or timeout <= 0:
        raise ValueError("max_workers and timeout must be positive")
    endpoints = iter(hosts)

    def scan(host: str) -> dict[str, Any]:
        try:
            with CertMonitor(
                host, port, enabled_validators, timeout=timeout
            ) as monitor:
                return {
                    "host": host,
                    "port": port,
                    "results": monitor.validate(),
                    "snapshot_at": monitor.snapshot_at,
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "host": host,
                "port": port,
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
