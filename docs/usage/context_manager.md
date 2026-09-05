# Context Manager vs Manual Close

Every CertMonitor session opens a network connection to the host you're checking. That connection needs to be closed when you're done, even if something goes wrong partway through. CertMonitor gives you two ways to handle this: a context manager, or manual open and close.

## Recommended: the context manager

The context manager (the `with ... as ...` form) is the one you'll want almost every time. It guarantees the connection is closed when the block ends, even if an error is raised inside it. You don't have to remember anything.

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

As soon as the `with` block exits, the connection is cleaned up for you.

## Manual open and close

Sometimes you need finer control, for example if you're managing connections yourself. In that case you can call `connect()` and `close()` directly. If you go this route, wrap your work in a `try`/`finally` so the connection always closes, even on an error.

```python
monitor = CertMonitor("example.com")
monitor.connect()
try:
    cert_info = monitor.get_cert_info()
    print(cert_info)
finally:
    monitor.close()
```

Notice how much more there is to get right here. That `finally` block is doing exactly what the context manager would do for you automatically.

## Example output

Both styles return the same result shape. Here is an illustrative excerpt:

```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "Jun  1 00:00:00 2024 GMT",
  "notAfter": "Sep  1 23:59:59 2025 GMT"
}
```

!!! tip "When in doubt, use `with`"
    Reach for the context manager unless you have a specific reason to manage connections manually, such as a long-lived monitoring object. It's safer and there's simply less to remember.

## Collect a fresh observation

Closing releases the connection but retains the last snapshot for inspection. That is useful when you want to read results after leaving the `with` block. It does not make those results current forever.

Inside an active monitoring workflow, use `monitor.refresh()` to discard the old snapshot and collect again, then call `monitor.validate()`. Reconnecting after `close()` keeps the snapshot; only `refresh()` discards it. `monitor.snapshot_at` records when the certificate was collected; keep it alongside stored results.
