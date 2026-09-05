# Full Workflow Example

Once you've seen the individual pieces, it helps to watch them work together. This page walks through a complete CertMonitor workflow: connecting to a host, pulling certificate info, running validators, reading cipher details, and handling errors when a connection goes wrong.

## Example: All-in-One

Let's say you want to inspect a host end to end. Here's everything in one script:

```python
from certmonitor import CertMonitor
import json
import base64

validators = [
    "subject_alt_names", "expiration", "hostname", "root_certificate", "key_info", "tls_version", "weak_cipher"
]

with CertMonitor("example.com", enabled_validators=validators) as monitor:
    cert_info = monitor.get_cert_info()
    print("Certificate Info:")
    print(json.dumps(cert_info, indent=2))

    validation_results = monitor.validate(
        validator_args={"subject_alt_names": {"alternate_names": ["www.example.com"]}}
    )
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
    if isinstance(der, bytes):
        print(base64.b64encode(der).decode("ascii"))
    else:
        print(der["error"], der["message"])
```

Notice the shape of this: you open one `with` block, and the certificate calls reuse the collected snapshot. When the block exits, CertMonitor cleans up for you. Protocol detection, trust verification, and an enabled PQ probe can use additional connections.

!!! tip "Why the context manager?"
    Using `with CertMonitor(...)` makes sure the collection connection is closed promptly when you're done. It's the recommended way to use CertMonitor, and it keeps your code tidy.

!!! info "DER, PEM, and cipher info are SSL/TLS only"
    `get_raw_pem()`, `get_raw_der()`, and `get_cipher_info()` deal with X.509 certificates and the TLS handshake, so they apply to SSL/TLS endpoints. CertMonitor auto-detects the protocol, so on an SSH endpoint these aren't available.

## Example Output (abbreviated)

Here's roughly what each call gives you back. The output is trimmed for readability.

### Certificate Info
```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "Jun  1 00:00:00 2024 GMT",
  "notAfter": "Sep  1 23:59:59 2025 GMT"
}
```

### Validation Results

Here are two entries from a scan against example.com at the time of writing. The script also returns the other enabled validators; their output is covered in the [validator catalog](../validators/index.md).

```json
{
  "hostname": {
    "is_valid": true,
    "alt_names": [
      "example.com",
      "*.example.com"
    ],
    "identity_source": "subjectAltName",
    "common_name": "example.com",
    "common_name_matches": true,
    "matched_name": "example.com",
    "status": "pass",
    "code": "hostname.pass"
  },
  "subject_alt_names": {
    "is_valid": true,
    "sans": {
      "DNS": [
        "example.com",
        "*.example.com"
      ],
      "IP Address": []
    },
    "count": 2,
    "contains_host": {
      "name": "example.com",
      "is_valid": true,
      "reason": "Exact match for example.com found in DNS SANs"
    },
    "contains_alternate": {
      "example.com": {
        "name": "example.com",
        "is_valid": true,
        "reason": "Exact match for example.com found in DNS SANs"
      },
      "www.example.com": {
        "name": "www.example.com",
        "is_valid": true,
        "reason": "www.example.com matches wildcard SAN(s): *.example.com"
      }
    },
    "warnings": [],
    "status": "pass",
    "code": "subject_alt_names.pass"
  }
}
```

The primary identity and alternate names are separate checks. A pass for one doesn't imply a pass for the other.

### Cipher Info
```json
{
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "encryption_algorithm": "AES",
    "message_authentication_code": "SHA384",
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

Connections don't always succeed, and that's fine. For ordinary network failures, it returns a structured error you can inspect and act on.

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
  "message": "[Errno -2] Name or service not known",
  "host": "badhost.invalid",
  "port": 443
}
```

Notice that the error is just a dictionary, with the `error` type, a human-readable `message`, and the `host` and `port` that were attempted. That makes it easy to log, alert on, or branch on in your own code.

!!! tip "Want more?"
    See the [Usage Guide](index.md) for more advanced examples and troubleshooting tips.
