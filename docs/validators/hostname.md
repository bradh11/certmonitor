# Hostname Validator

Confirms the certificate was actually issued for the host you connected to. `hostname` matches the host against the certificate's Subject Alternative Names (SANs) and Common Name (CN), including wildcard certificates (`*.example.com`). A mismatch is what your browser shows as "this certificate is not valid for this site."

!!! note "Enabled by default"
    `hostname` is one of the three default validators. The host you pass to `CertMonitor(...)` is the name it checks against.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["hostname"])
```

A matching hostname reports which name matched and the SANs it considered:

```json
{
  "is_valid": true,
  "matched_name": "example.com",
  "alt_names": ["example.com", "www.example.com"]
}
```

A mismatch fails with a `reason`:

```json
{
  "is_valid": false,
  "reason": "Hostname wrong.host.badssl.com doesn't match any of the certificate's subject alternative names or common name",
  "alt_names": ["*.badssl.com", "badssl.com"]
}
```

## How matching works

1. **Common Name** — if the CN matches the host exactly, it passes.
2. **DNS SANs** — the host is checked against every DNS SAN (case-insensitive).
3. **Wildcards** — a `*.example.com` SAN matches exactly one label (`api.example.com`), but **not** the bare apex (`example.com`) or nested subdomains (`a.b.example.com`).

!!! tip "Checking with an IP address?"
    Connecting by IP will usually fail `hostname` unless the certificate carries that IP as a SAN — most don't. See [Using IP Addresses](../usage/ip.md) for how CertMonitor handles IP targets.

## API

::: certmonitor.validators.hostname.HostnameValidator
