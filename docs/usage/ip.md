# Using IP Addresses

Most of the time you'll point CertMonitor at a domain name. But sometimes you don't have one, or you want to check a specific host behind a load balancer. Good news: CertMonitor accepts IP addresses too, both IPv4 and IPv6, exactly where you'd put a hostname.

## An IPv4 address

Let's say you want to check a host by its IPv4 address. Just pass it in like any other target:

```python
from certmonitor import CertMonitor

with CertMonitor("93.184.216.34") as monitor:  # example.com's IPv4
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

## An IPv6 address

IPv6 works the same way. Pass the address as a string:

```python
with CertMonitor("2606:2800:220:1:248:1893:25c8:1946") as monitor:  # example.com's IPv6
    cert_info = monitor.get_cert_info()
    print(cert_info)
```

## What you get back

The output looks just like it does for a domain name:

```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"organizationName": "DigiCert Inc"},
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59"
  // ...
}
```

## Things to watch out for

A few edge cases are worth knowing about before you rely on IP targets:

- Not every host has a certificate issued for its IP address. When the certificate only covers a hostname, validation against the IP may fail.
- IPv6 support depends on your system and network configuration. If your network can't route IPv6, the connection won't get off the ground.
- If a connection can't be established, CertMonitor returns a structured error rather than raising, so you can inspect what happened.

!!! tip "Everything else just works"
    You can use all the same validators and features with an IP address that you'd use with a domain name. Nothing else about your code needs to change.
