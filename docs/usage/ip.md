# Using IP Addresses

Most of the time you'll point CertMonitor at a domain name. But sometimes you want to check a specific host behind a load balancer, or your certificate really is issued for an IP address. Those are two different jobs. Let's walk through both.

## Check a certificate issued for an IP

Pass the address where you'd normally put the hostname. Both IPv4 and IPv6 are accepted. The addresses below are reserved documentation ranges; replace them with endpoints you operate.

### An IPv4 address

```python
from certmonitor import CertMonitor

with CertMonitor("192.0.2.10") as monitor:
    print(monitor.validate())
```

### An IPv6 address

IPv6 works the same way. Pass the address as a string, without brackets:

```python
from certmonitor import CertMonitor

with CertMonitor("2001:db8::10") as monitor:
    print(monitor.validate())
```

The `hostname` validator checks the address against **IP Address SANs**. A DNS SAN containing the same text, or an IP written in the Common Name, does not satisfy that identity check. IPv6 also needs a working route from your machine.

## Check a particular backend for a DNS name

Suppose `api.example.com` normally resolves through a load balancer, but you want to inspect one backend directly. Keep the DNS name as the identity and set `connection_host` to the backend address:

```python
from certmonitor import CertMonitor

with CertMonitor(
    "api.example.com",
    connection_host="192.0.2.10",  # Replace with your backend address.
) as monitor:
    print(monitor.validate())
```

The `host` argument stays what the certificate must be valid for; the connection options only change how you reach it:

| Option | What it controls |
|---|---|
| `host` | The identity checked by `hostname`, and the default for the two options below. |
| `connection_host` | The address used for the TCP connection. |
| `server_hostname` | TLS Server Name Indication (SNI), so the server can select its certificate. Defaults to `host`. |

Setting SNI does not itself validate identity. If you ever need to check a different name than the one you connected with, that is a validator decision, so it lives on the `hostname` validator: `validator_args={"hostname": {"expected_identity": "api.example.com"}}`.

!!! tip "Private CA on the backend?"
    Pass `cafile="/path/to/your/ca-bundle.pem"` for the separate trust check. See [RootCertificate](../validators/root_certificate.md) for an example. A connection address override also applies to that verified handshake.

## Read failures in context

A connection error means CertMonitor could not collect the certificate. A failed `hostname` result means it collected a certificate that didn't match the requested identity. Read `status` and `reason` before changing your target.

The optional PQ probe follows the same split: it connects to `connection_host` and offers `server_hostname` as SNI.
