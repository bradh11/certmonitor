# TLSVersion Validator

Checks that the connection negotiated a TLS version you consider acceptable. By default that's **TLS 1.2 or TLS 1.3** — TLS 1.1 and older are deprecated and fail. A useful guard against legacy endpoints that silently fall back to insecure protocols.

!!! note "Opt-in"
    Enable via `enabled_validators=["tls_version", ...]` or `ENABLED_VALIDATORS`.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["tls_version"]) as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["tls_version"])
```

A modern endpoint passes:

```json
{
  "is_valid": true,
  "protocol_version": "TLSv1.3"
}
```

A legacy endpoint fails with a `reason`:

```json
{
  "is_valid": false,
  "protocol_version": "TLSv1.0",
  "reason": "TLS version TLSv1.0 is not allowed. Update your allowed TLS versions or negotiate a supported version."
}
```

## Customizing the allowed versions

The allow-list lives in `certmonitor.cipher_algorithms.ALLOWED_TLS_VERSIONS` (default `{"TLSv1.2", "TLSv1.3"}`) and can be overridden at runtime:

```python
from certmonitor.cipher_algorithms import update_allowed_lists

update_allowed_lists(custom_tls_versions={"TLSv1.3"})  # require TLS 1.3 only
```

!!! tip "Pairs with WeakCipher"
    `tls_version` checks the protocol; [WeakCipher](weak_cipher.md) checks the negotiated cipher suite. Enable both for a complete transport-security picture, and see [Post-Quantum Cryptography](../concepts/post-quantum.md) for why even TLS 1.3 isn't the whole story.

## API

::: certmonitor.validators.tls_version.TLSVersionValidator
