# Retrieving Raw Certificate Data

Sometimes you don't want CertMonitor's parsed view of a certificate. You want the certificate itself, in its original encoding, so you can hand it to another tool. CertMonitor lets you pull the raw certificate in two formats: PEM and DER.

## Get PEM format

PEM is the base64-encoded, human-readable format you've probably seen in `.pem` and `.crt` files. It's what most file-based tools expect.

Let's grab it:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    pem = monitor.get_raw_pem()
    print(pem)
```

### Example output

```pem
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuQ...(truncated for brevity)...IDAQAB
-----END CERTIFICATE-----
```

## Get DER format

DER is a binary format. It's what you reach for when a low-level API or cryptographic library wants raw bytes rather than text.

```python
with CertMonitor("example.com") as monitor:
    der = monitor.get_raw_der()
    if isinstance(der, bytes):
        import base64
        print(base64.b64encode(der).decode("ascii"))
    else:
        print(der["error"], der["message"])
```

### Example output (base64-encoded for readability)

```text
MIIDdzCCAl+gAwIBAgIEAgAAuQ...(truncated for brevity)...IDAQAB
```

!!! note "DER is bytes, not text"
    On success, `get_raw_der()` returns raw bytes; on failure, it returns an error dictionary. Check the type before encoding or saving it. Printing them directly is noisy, so base64-encode the value first when you need something readable.

## Fingerprint

Every collected certificate carries its SHA-256 fingerprint: `monitor.fingerprint_sha256`, `get_cert_info()["fingerprint_sha256"]`, and the `fingerprint_sha256` field in `scan_hosts()` results and `certmonitor check --json`. It is the lowercase hex digest of the DER bytes, the same value `openssl x509 -fingerprint -sha256` prints without the colons.

```python
with CertMonitor("example.com") as monitor:
    print(monitor.get_cert_info()["fingerprint_sha256"])
```

Store it with your results: a changed fingerprint on the next scan means the certificate was replaced, which is the cheapest renewal detector there is.

## How retrieval fits together

Here's the path a certificate takes, from the connection to whichever format you ask for:

```mermaid
flowchart TD
    A[Connect to Host:Port] --> B[Detect Protocol]
    B --> C[Retrieve Certificate]
    C --> D[Parse Certificate Info]
    D --> E{User Request}
    E -->|PEM| F[Return PEM]
    E -->|DER| G[Return DER]
    E -->|Info| H[Return Parsed Info]
```

As you can see, the same retrieved certificate can come back as PEM, as DER, or as parsed info. You pick the shape that fits your task.

## When to use each format

So which one do you want? It comes down to what's on the receiving end:

- **PEM**: Use it for most file-based operations, OpenSSL, and human inspection.
- **DER**: Use it for binary APIs, cryptographic libraries, or anywhere a raw byte array is required.

!!! tip "You can always convert"
    If you have one format and need the other, Python's standard-library `ssl.PEM_cert_to_DER_cert()` and `ssl.DER_cert_to_PEM_cert()` convert between PEM and DER without an extra package.
