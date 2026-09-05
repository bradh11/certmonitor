# Troubleshooting

Common issues and how to resolve them. If your problem isn't here, the [FAQ](faq.md) and [Error Handling](error_handling.md) pages cover more.

## Connection problems

**Symptom:** `get_cert_info()` returns a dict with an `error` key like `ConnectionError` or `ProtocolDetectionError`.

- Confirm the host and port are reachable: `openssl s_client -connect host:443`.
- Check firewalls, proxies, and DNS. CertMonitor makes a direct TCP connection.
- For non-standard ports, pass them explicitly: `CertMonitor("host", 8443)`.

```python
with CertMonitor("example.com") as monitor:
    cert = monitor.get_cert_info()
    if isinstance(cert, dict) and "error" in cert:
        print(cert["error"], "-", cert["message"])
```

## "Validator not found"

A result like `{"is_valid": false, "reason": "Validator 'foo' is not implemented."}` means the name isn't registered.

- Check spelling against the [validator list](../validators/index.md).
- Remember most validators are **opt-in**. Enable them with `enabled_validators=[...]`. Only `expiration`, `hostname`, and `root_certificate` run by default.

## A validator reports `is_valid: false` unexpectedly

Every failing validator includes a `reason` explaining exactly why, so read it first:

```python
results = monitor.validate()
for name, r in results.items():
    if not r["is_valid"]:
        print(f"{name}: {r.get('reason', '(no reason)')}")
```

Common surprises:

- **`hostname` fails on an IP address.** Most certs don't list IPs as SANs. See [Using IP Addresses](ip.md).
- **`pq_signature` / `pq_chain` is `false` for a normal site.** This is expected: the cert is classical (EC/RSA), not post-quantum. See [Post-Quantum Cryptography](../concepts/post-quantum.md).

## Inspecting output

Validator and certificate output is plain JSON-serializable dicts. Pretty-print to explore:

```python
import json
print(json.dumps(monitor.validate(), indent=2))
```

## SSH vs SSL/TLS

CertMonitor auto-detects the protocol. Features like raw DER/PEM and cipher info are **SSL/TLS only**, so calling them against an SSH host returns a `ProtocolError`. See [Protocol Detection](protocol.md).

!!! tip "Still stuck?"
    Open an issue with the host/port (if shareable), your Python version, and the full error dict. The `error` and `message` fields are the fastest way to diagnose.
