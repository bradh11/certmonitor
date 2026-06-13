# API Reference: Protocol Handlers

Protocol handlers are how CertMonitor talks to a host. When you connect, CertMonitor detects whether the endpoint speaks SSL/TLS or SSH and hands off to the matching handler, which knows how to fetch the certificate (and, for TLS, the cipher information). You normally won't use these directly, since `CertMonitor` drives them for you. They're documented here for contributors and for anyone writing a custom handler.

See [Protocol Detection](../usage/protocol.md) for how the right handler gets chosen at connect time.

## Base handler

The shared interface every handler implements.

::: certmonitor.protocol_handlers.base

## SSL/TLS handler

Handles SSL/TLS endpoints: the handshake, certificate retrieval, and cipher info.

::: certmonitor.protocol_handlers.ssl_handler

## SSH handler

Handles SSH endpoints.

::: certmonitor.protocol_handlers.ssh_handler
