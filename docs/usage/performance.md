# Performance Tips

CertMonitor is built to stay out of your way when you're checking a lot of hosts. A check often spends much of its time waiting on DNS, TCP, and TLS. The biggest win is usually letting a few independent checks overlap.

Start with a small concurrency limit, measure your own endpoints, and increase it if your network and servers can handle the load. Each worker needs its own monitor: a `CertMonitor` keeps mutable connection and snapshot state and should not be shared between concurrent tasks.

## Scan a batch

For a synchronous script, `scan_hosts()` handles the workers and connection cleanup for you:

```python
from certmonitor import scan_hosts

hosts = ["example.com", "www.python.org", "pypi.org"]
for scan in scan_hosts(hosts, max_workers=4, timeout=5):
    print(scan["host"], scan["snapshot_at"])
    for name, result in scan["results"].items():
        print(" ", name, result["status"], result.get("reason", ""))
```

Results arrive in completion order, so a slow host doesn't hold up completed results. Each result includes the host, port, observation timestamp, and the usual validator results. At most `max_workers` endpoints are in flight; the input can be an iterator instead of a list.

The default validators run unless you supply `enabled_validators`. This helper has a deliberately small interface. If you need per-host alternate names, custom CA files, or separate connection addresses, create your own `CertMonitor` inside each worker.

## Use it from async code

CertMonitor's API is synchronous. In an async application, move the blocking work to a thread so it doesn't block the event loop:

```python
import asyncio
from certmonitor import CertMonitor


def check_host(host: str):
    with CertMonitor(host, timeout=5) as monitor:
        return host, monitor.validate()


async def main():
    limit = asyncio.Semaphore(4)

    async def check_limited(host):
        async with limit:
            return await asyncio.to_thread(check_host, host)

    hosts = ["example.com", "www.python.org", "pypi.org"]
    tasks = [asyncio.create_task(check_limited(host)) for host in hosts]
    for task in asyncio.as_completed(tasks):
        host, results = await task
        print(host, results)


if __name__ == "__main__":
    asyncio.run(main())
```

The semaphore limits active scans to four. This example still creates one task per host, so use a bounded producer/worker queue for a very large inventory. The synchronous `scan_hosts()` helper already limits pending work.

## Understand the limits

`timeout` bounds each network operation, including each connection attempt made while collecting a certificate. It is not a deadline for an entire scan; collection makes at most two attempts (a full-range offer, then one capped at TLS 1.2), so a host that silently drops handshakes can take up to twice `timeout` to give up. Platform DNS resolution is not interruptible, and cancelling an `asyncio.to_thread()` await does not stop a scan already running in the worker.

The Rust TLS probe releases the GIL during its network work. The certificate parser does not make that same guarantee; don't assume all Rust calls run concurrently just because they're written in Rust.

!!! tip "Count connections as well as hosts"
    Protocol detection, collection retries, verified trust, and an enabled PQ probe can make separate connections. Account for those when choosing a rate limit, especially against a small appliance or a shared service.

## Reuse a snapshot deliberately

Calls on a monitor reuse collected certificate data. For a new observation, call `refresh()` and then validate again. Keep `snapshot_at` with your results so a dashboard can distinguish the time you observed a certificate from the time it displayed the result.

See [Context Manager vs Manual Close](context_manager.md) for the connection lifecycle and [the API reference](../reference/certmonitor.md) for `scan_hosts()`.
