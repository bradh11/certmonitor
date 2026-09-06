# Environment Variable Configuration

CertMonitor reads one environment variable, `ENABLED_VALIDATORS`, at import time to set which validators run when you don't pass `enabled_validators` explicitly. Handy for configuring CI jobs, containers, or cron monitors without changing code.

## ENABLED_VALIDATORS

A comma-separated list of validator names:

```sh
export ENABLED_VALIDATORS="expiration,hostname,tls_version,weak_cipher"
```

```python
from certmonitor import CertMonitor

# No enabled_validators arg -> falls back to ENABLED_VALIDATORS, then to defaults
with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.get_enabled_validators())
```

### Precedence

The enabled set is resolved in this order:

1. The `enabled_validators=[...]` argument to `CertMonitor(...)`, if given.
2. Otherwise the non-empty `ENABLED_VALIDATORS` environment variable captured when the configuration module was imported.
3. Otherwise the built-in defaults: `expiration`, `hostname`, `root_certificate`.

!!! tip "Turning on post-quantum checks fleet-wide"
    To enable the opt-in PQ validators across every monitor without touching code:
    ```sh
    export ENABLED_VALIDATORS="expiration,hostname,root_certificate,pq_key_exchange,pq_signature,pq_chain"
    ```

!!! note "Names must be valid"
    An unknown name produces a per-validator result with `status: "error"` and `error: "UnknownValidator"` rather than an exception, so a typo fails the run instead of silently skipping the check. Check the [validator list](../validators/index.md) for the exact names.
