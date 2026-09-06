# API Reference: Protocol Handlers

Protocol handlers are how CertMonitor talks to a host. When you connect, CertMonitor detects whether the endpoint speaks SSL/TLS or SSH and hands off to the matching handler, which knows how to fetch the certificate (and, for TLS, the cipher information). The pieces every connection shares live in the same package: opening streams, running and discovering STARTTLS preambles, and detection itself. You normally won't use any of this directly, since `CertMonitor` drives it for you. It's documented here for contributors and for anyone writing a custom handler.

See [Protocol Detection](../usage/protocol.md) for how the right handler gets chosen at connect time.

## Base handler

The shared interface every handler implements.

::: certmonitor.protocol_handlers.base

## SSL/TLS handler

Handles SSL/TLS endpoints: the handshake, certificate retrieval, and cipher info.

::: certmonitor.protocol_handlers.ssl_handler

## SSH handler

Reads SSH version banners. It does not retrieve or validate SSH host keys or SSH certificates.

::: certmonitor.protocol_handlers.ssh_handler

## Connections

Every socket CertMonitor opens comes from here: a plaintext stream with any STARTTLS preamble already negotiated, or a TLS stream handshaken with the caller's context.

::: certmonitor.protocol_handlers.connection

## Detection

Decides which handler a port needs from its first bytes, handing plaintext greetings to STARTTLS discovery.

::: certmonitor.protocol_handlers.detection

## STARTTLS

The preambles for SMTP, IMAP, POP3, FTP, PostgreSQL, and LDAP, and the discovery that names a service without looking at its port. See [STARTTLS Services](../usage/starttls.md) for usage.

::: certmonitor.protocol_handlers.starttls
