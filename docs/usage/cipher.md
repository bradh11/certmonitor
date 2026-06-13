# Retrieving Cipher Information

Every TLS connection negotiates a cipher suite: the exact set of algorithms used to encrypt and authenticate the session. CertMonitor lets you see what was chosen, broken down into its parts, so you don't have to decode the cipher suite name yourself.

## Getting cipher info

Use the `get_cipher_info()` method to retrieve structured information about the negotiated cipher suite:

```python
from certmonitor import CertMonitor
import json

with CertMonitor("example.com") as monitor:
    cipher_info = monitor.get_cipher_info()
    print(json.dumps(cipher_info, indent=2))
```

### Example output

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

Let's walk through what came back:

- The `cipher_suite` object holds the negotiated cipher suite name along with its parsed components.
- `protocol_version` shows the TLS version in use.
- `key_bit_length` is the size of the encryption key.

!!! info "Want to know what the parts mean?"
    The [How TLS & HTTPS Work](../concepts/how-tls-works.md) page explains key exchange, authentication, and why the cipher suite matters.

See also: [API Reference: CertMonitor.get_cipher_info()](../reference/certmonitor.md#get_cipher_info)
