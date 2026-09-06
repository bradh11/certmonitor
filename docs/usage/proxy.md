---
title: "Scan Certificates Through an HTTP or SOCKS5 Proxy"
description: "Route CertMonitor's connections through an HTTP CONNECT or SOCKS5 proxy, with authentication, for scanning from restricted enterprise networks. Standard library only."
---

# Proxies

Some networks only let traffic out through a proxy. The `proxy` option routes every connection CertMonitor makes for an endpoint through one: protocol detection, certificate collection, the verified trust handshake, and any STARTTLS preamble. Nothing is installed for it; both tunnel types are implemented on the standard library.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", proxy="http://proxy.corp.example:3128") as monitor:
    print(monitor.validate()["root_certificate"]["status"])
```

```sh
certmonitor check example.com --proxy socks5://proxy.corp.example:1080
```

## Proxy URLs

| Form | Tunnel |
|---|---|
| `http://host:port` | HTTP `CONNECT` (RFC 9110). Port defaults to 3128. |
| `http://user:pass@host:port` | `CONNECT` with `Proxy-Authorization: Basic`. |
| `socks5://host:port` | SOCKS5 (RFC 1928). Port defaults to 1080. |
| `socks5://user:pass@host:port` | SOCKS5 with username/password authentication (RFC 1929). |
| `socks5h://...` | Same as `socks5://`. |

The proxy resolves the target name in both cases: CertMonitor sends the host name inside the `CONNECT` request or the SOCKS5 request, so no DNS query for the target leaves the scanning host. IP literals are sent as addresses. Percent-encode special characters in credentials (`s%40cret` for `s@cret`).

## What the results say

`cert_data["source"]` records the route with the password removed:

```json
{"type": "connection", "host": "example.com", "port": 443, "proxy": "http://alice@proxy.corp.example:3128"}
```

That matters because a TLS-inspecting proxy replaces the certificate you see with its own. If the fingerprint through the proxy differs from the one a direct connection shows, the proxy is in the middle, and the trust and hostname verdicts describe the proxy's certificate.

A proxy that refuses the tunnel, rejects the credentials, or answers unexpectedly turns into the usual `ConnectionError` result with the proxy's reply in the message, for example `proxy requires authentication (407)` or `proxy refused the SOCKS5 connection to example.com:443: connection refused`.

## Fleets and the command line

`scan_hosts(proxy=...)` applies one proxy to every endpoint; an endpoint dict can carry its own `proxy`. `certmonitor check --proxy URL` applies to every target in that run.

## Not yet through the proxy

The native post-quantum probe opens its own connection and does not tunnel yet, so `pq_key_exchange` reports `status: unsupported` with a reason when a proxy is configured.
