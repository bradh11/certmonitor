# Full Workflow Example

Once you've seen the individual pieces, it helps to watch them work together. This page walks through a complete CertMonitor workflow: connecting to a host, pulling certificate info, running validators, reading cipher details, and handling errors when a connection goes wrong.

## Example: All-in-One

Let's say you want to inspect a host end to end. Here's everything in one script:

```python
from certmonitor import CertMonitor
import json

validators = [
    "subject_alt_names", "expiration", "hostname", "root_certificate", "key_info", "tls_version", "weak_cipher"
]

with CertMonitor("example.com", enabled_validators=validators) as monitor:
    cert_info = monitor.get_cert_info()
    print("Certificate Info:")
    print(json.dumps(cert_info, indent=2))

    validation_results = monitor.validate()
    print("Validation Results:")
    print(json.dumps(validation_results, indent=2))

    cipher_info = monitor.get_cipher_info()
    print("Cipher Info:")
    print(json.dumps(cipher_info, indent=2))

    pem = monitor.get_raw_pem()
    print("PEM Format:")
    print(pem)

    der = monitor.get_raw_der()
    print("DER Format (base64):")
    import base64
    print(base64.b64encode(der).decode())
```

Notice the shape of this: you open one `with` block, and every call inside it reuses the same connection. When the block exits, CertMonitor cleans up for you.

!!! tip "Why the context manager?"
    Using `with CertMonitor(...)` makes sure the connection is opened once and closed promptly when you're done. It's the recommended way to use CertMonitor, and it keeps your code tidy.

!!! info "DER, PEM, and cipher info are SSL/TLS only"
    `get_raw_pem()`, `get_raw_der()`, and `get_cipher_info()` deal with X.509 certificates and the TLS handshake, so they apply to SSL/TLS endpoints. CertMonitor auto-detects the protocol, so on an SSH endpoint these aren't available.

## Example Output (abbreviated)

Here's roughly what each call gives you back. The output is trimmed for readability.

### Certificate Info
```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59"
  // ...
}
```

### Validation Results
```json
{
  "expiration": {"is_valid": true, "days_to_expiry": 120, "expires_on": "2025-09-01T23:59:59", "warnings": []},
  "subject_alt_names": {"is_valid": true, "sans": {"DNS": ["example.com", "www.example.com"], "IP Address": []}, "count": 2, "contains_host": {"name": "example.com", "is_valid": true, "reason": "Matched DNS SAN"}, "contains_alternate": {"www.example.com": {"name": "www.example.com", "is_valid": true, "reason": "Matched DNS SAN"}}, "warnings": []}
  // ...
}
```

### Cipher Info
```json
{
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "encryption_algorithm": "AES-256-GCM",
    "message_authentication_code": "AEAD",
    "key_exchange_algorithm": "Not applicable (TLS 1.3 uses ephemeral key exchange by default)"
  },
  "protocol_version": "TLSv1.3",
  "key_bit_length": 256
}
```

### PEM Format
```pem
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuQ...(truncated for brevity)...IDAQAB
-----END CERTIFICATE-----
```

### DER Format (base64)
```text
MIIDdzCCAl+gAwIBAgIEAgAAuQ...(truncated for brevity)...IDAQAB
```

## Error Handling Example

Connections don't always succeed, and that's fine. CertMonitor never throws a surprise at you here. When a connection fails, it returns a structured error you can inspect and act on.

Let's point it at a host that doesn't exist:

```python
with CertMonitor("badhost.invalid") as monitor:
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

You get back something like this:

```json
{
  "error": "ConnectionError",
  "reason": "[Errno -2] Name or service not known",
  "host": "badhost.invalid",
  "port": 443
}
```

Notice that the error is just a dictionary, with the `error` type, a human-readable `reason`, and the `host` and `port` that were attempted. That makes it easy to log, alert on, or branch on in your own code.

!!! tip "Want more?"
    See the [Usage Guide](index.md) for more advanced examples and troubleshooting tips.
