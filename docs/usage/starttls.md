---
title: "Check Certificates on STARTTLS Services (SMTP, IMAP, LDAP, PostgreSQL)"
description: "Validate TLS certificates on services that upgrade a plaintext connection with STARTTLS: SMTP, IMAP, POP3, FTP, PostgreSQL, and LDAP, using CertMonitor's starttls option."
---

# STARTTLS Services

Not every TLS service starts encrypted. Mail servers, directory servers, and databases often greet you in plaintext and switch to TLS only after a short application-protocol exchange. Connecting to such a port and immediately sending a TLS handshake fails, which is why a plain `CertMonitor("mail.example.com", 587)` cannot see that server's certificate.

The `starttls` option runs the right preamble first. After it, every validator works exactly as it does for an HTTPS endpoint.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("mail.example.com", 587, starttls="smtp") as monitor:
    print(monitor.validate()["expiration"])
```

From the shell:

```sh
certmonitor check mail.example.com:587 --starttls smtp
certmonitor check db.internal:5432 --starttls postgres --cafile /etc/pki/private-ca.pem
```

## Supported protocols

| `starttls` | Service | Typical port | What CertMonitor sends |
|---|---|---|---|
| `smtp` | Mail submission and relay | 587, 25 | `EHLO`, then `STARTTLS` (RFC 3207) |
| `imap` | Mail access | 143 | `STARTTLS` (RFC 2595) |
| `pop3` | Mail access | 110 | `STLS` (RFC 2595) |
| `ftp` | File transfer | 21 | `AUTH TLS` (RFC 4217) |
| `postgres` | PostgreSQL | 5432 | The 8-byte `SSLRequest` message |
| `ldap` | Directory | 389 | An `ExtendedRequest` for the StartTLS OID `1.3.6.1.4.1.1466.20037` (RFC 4511) |

Ports that are TLS from the first byte (465 for SMTPS, 993 for IMAPS, 995 for POP3S, 636 for LDAPS) need no `starttls` at all.

## What changes with STARTTLS

- **Protocol detection is skipped.** The first bytes on a STARTTLS port are the service banner, not a TLS record, so CertMonitor trusts your `starttls` choice instead of peeking.
- **Every connection runs the preamble.** The permissive collection connection and the separate verified trust handshake both negotiate STARTTLS, so `root_certificate` works the same way it does for HTTPS.
- **The post-quantum probe reports `unsupported`.** The native probe does not yet speak the preambles; `pq_key_exchange` returns `status: unsupported` with a reason rather than a wrong answer.
- **A refusal is an error, not a guess.** If the server does not offer STARTTLS, or declines it, the collection fails with the server's own reply in the message (for example `SMTP server does not advertise STARTTLS` or `PostgreSQL server declined SSL`).

## Fleets

`scan_hosts()` accepts `starttls` for the whole scan or per endpoint:

```python
from certmonitor import scan_hosts

targets = [
    {"host": "mail.example.com", "port": 587, "starttls": "smtp"},
    {"host": "db.internal", "port": 5432, "starttls": "postgres", "cafile": "/etc/pki/private-ca.pem"},
    "www.example.com",
]
for scan in scan_hosts(targets):
    print(scan["host"], scan["results"]["expiration"]["status"])
```

## Reference

::: certmonitor.starttls
    options:
      members:
        - negotiate
        - StartTLSError
        - PROTOCOLS
