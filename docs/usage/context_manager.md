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

Both styles return the same results:

```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59"
  // ...
}
```

!!! tip "When in doubt, use `with`"
    Reach for the context manager unless you have a specific reason to manage connections manually, such as advanced connection pooling. It's safer and there's simply less to remember.
