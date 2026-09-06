# Troubleshooting

Common issues and how to resolve them. If your problem isn't here, the [FAQ](faq.md) and [Error Handling](error_handling.md) pages cover more.

## Connection problems

**Symptom:** `get_cert_info()` returns a dict with an `error` key like `ConnectionError` or `ProtocolDetectionError`.

- Confirm the host and port are reachable: `openssl s_client -connect host:443`.
- Check firewalls, proxies, and DNS. CertMonitor makes a direct TCP connection.
- For non-standard ports, pass them explicitly: `CertMonitor("host", 8443)`.

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert = monitor.get_cert_info()
    if isinstance(cert, dict) and "error" in cert:
        print(cert["error"], "-", cert["message"])
```

## "Validator not found"

A result like `{"is_valid": false, "status": "error", "error": "UnknownValidator", "reason": "Validator 'foo' is not implemented."}` means the name isn't registered. It counts as an error, so `certmonitor check` exits 1 and a fleet scan flags the host: a misspelled validator must not pass silently.

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

- **`subject_alt_names` reports unsupported.** Enable it with a non-empty `alternate_names` list; it checks extra names only. Use `hostname` for the primary identity.
- **A validator key is missing.** Confirm it is enabled. `validator_args` configures a validator but does not enable it.
- **`root_certificate` reports `SnapshotMismatch`.** The verified connection returned a different leaf. Refresh and retry; for a rotating backend pool, target a single backend with `connection_host`.
- **A private CA is untrusted.** Configure `cafile` or `capath` for the trust check. Issuer names alone cannot establish trust.
- **`hostname` fails on an IP address.** Most certs don't list IPs as SANs. See [Using IP Addresses](ip.md).
- **`pq_signature` / `pq_chain` is `false` for a normal site.** This is expected: the cert is classical (EC/RSA), not post-quantum. See [Post-Quantum Cryptography](../concepts/post-quantum.md).

## Inspecting output

Validator results and `get_cert_info()` output are JSON-serializable dictionaries. Raw DER and the internal `cert_data` snapshot can contain bytes, so do not serialize those directly. Pretty-print to explore:

```python
import json
print(json.dumps(monitor.validate(), indent=2))
```

## STARTTLS ports

**Symptom:** a mail, directory, or database port returns an `SSLError` such as `Failed to establish SSL connection with any protocol`, or a `StartTLSError` naming the server's reply.

CertMonitor discovers STARTTLS services on its own, so the usual cause is that discovery could not name the service, or the server refused to upgrade:

- **Check what was found.** After connecting, `monitor.starttls` holds the discovered protocol, or `None` if nothing was named.
- **Pin the protocol.** `CertMonitor("mail.example.com", 587, starttls="smtp")` skips detection and discovery and runs that preamble directly. If this works when discovery did not, the server's greeting is unusual or slow; pinning is the right fix.
- **Read the server's reply.** A `StartTLSError` carries it, for example `SMTP server does not advertise STARTTLS` or `PostgreSQL server declined SSL`. The service is reachable but is not offering TLS on that port.
- **Try the implicit-TLS port.** 465, 993, 995, and 636 speak TLS from the first byte and need no preamble at all.

See [STARTTLS Services](starttls.md) for how discovery works and when to pin.

## SSH vs SSL/TLS

CertMonitor auto-detects the protocol. Features like raw DER/PEM and cipher info are **SSL/TLS only**, so calling them against an SSH host returns a `ProtocolError`. See [Protocol Detection](protocol.md).

!!! tip "Still stuck?"
    Open an issue with the host/port (if shareable), your Python version, and the full error dict. The `error` and `message` fields are the fastest way to diagnose.
