---
title: "Check Certificates on STARTTLS Services (SMTP, IMAP, LDAP, PostgreSQL)"
description: "Validate TLS certificates on services that upgrade a plaintext connection with STARTTLS: SMTP, IMAP, POP3, FTP, PostgreSQL, and LDAP, using CertMonitor's starttls option."
---

# STARTTLS Services

Not every TLS service starts encrypted. Mail servers, directory servers, and databases often greet you in plaintext and switch to TLS only after a short application-protocol exchange. Connecting to such a port and immediately sending a TLS handshake fails.

CertMonitor handles this on its own. When a port does not answer a TLS handshake, it works out which service is listening and runs that service's STARTTLS preamble first. After the preamble, every validator works exactly as it does for an HTTPS endpoint.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("mail.example.com", 587) as monitor:
    print(monitor.validate()["expiration"])
    print(monitor.starttls)  # "smtp", discovered
```

From the shell:

```sh
certmonitor check mail.example.com:587
certmonitor check db.internal:5432 --cafile /etc/pki/private-ca.pem
```

## How discovery works

Discovery never looks at the port number, so a mail server on 2525 or a directory server on 10389 is found just like one on its usual port. It reads the service instead:

1. **A service that speaks first is named from its greeting.** `* OK` is IMAP, `+OK` is POP3, and an `SSH-` banner is SSH. SMTP and FTP both greet with `220`; the greeting text usually says which, and when it does not, CertMonitor sends `EHLO` and treats a `250` reply as SMTP.
2. **A silent service is asked.** CertMonitor sends the PostgreSQL `SSLRequest` and treats any of its one-byte answers as PostgreSQL. If that gets nothing, a fresh connection sends the LDAP StartTLS request and treats any LDAP reply as LDAP.
3. **Anything else keeps the original TLS error.** A port that is neither TLS nor a known STARTTLS service reports the handshake failure it would have reported before.

Discovery costs nothing on ports that speak TLS directly: it only starts after the TLS handshake fails, and the whole exchange is bounded by `timeout`. The result is stored on the monitor as `starttls` and reused by every later connection, including the verified trust handshake.

## Choosing the protocol yourself

Pass `starttls` to skip detection and discovery entirely. This is the override for a service you already know, or one that greets slowly enough that you would rather not wait:

```python
with CertMonitor("mail.example.com", 587, starttls="smtp") as monitor:
    print(monitor.validate()["expiration"])
```

```sh
certmonitor check mail.example.com:587 --starttls smtp
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

- **An explicit `starttls` skips detection.** The first bytes on a STARTTLS port are the service banner, not a TLS record, so CertMonitor trusts your choice instead of peeking or discovering.
- **Every connection runs the preamble.** The permissive collection connection and the separate verified trust handshake both negotiate STARTTLS, so `root_certificate` works the same way it does for HTTPS.
- **The post-quantum probe reports `unsupported`.** The native probe does not yet speak the preambles; `pq_key_exchange` returns `status: unsupported` with a reason rather than a wrong answer.
- **A refusal is an error, not a guess.** If the server does not offer STARTTLS, or declines it, the collection fails with the server's own reply in the message (for example `SMTP server does not advertise STARTTLS` or `PostgreSQL server declined SSL`).

## Fleets

Fleets need nothing special: each endpoint discovers its own service. `scan_hosts()` also accepts `starttls` for the whole scan or per endpoint when you want to pin it:

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
