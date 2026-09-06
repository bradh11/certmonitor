# Security Configuration for CertMonitor

CertMonitor needs to inspect the certificates that normal clients reject: expired certificates, untrusted issuers, and legacy endpoints. That means collection and verification have different jobs. Understanding the boundary helps you interpret the results correctly.

## Why collection is permissive

The SSL/TLS handler disables certificate verification for the collection connection. Otherwise, an expired certificate could prevent you from collecting the very evidence you need for an alert. The collection context offers every protocol version the local Python build supports, so legacy TLS 1.0 and 1.1 servers can still be inspected where the build allows them.

Which old versions can actually connect depends on the local Python build and its TLS library configuration. CertMonitor cannot promise support for every obsolete protocol or certificate encoding.

!!! warning "Collected does not mean trusted"
    A successful `get_cert_info()` call means you retrieved certificate data. Read `hostname`, `expiration`, and `root_certificate` before deciding whether the endpoint meets those checks. The collection socket is not a verified connection for your application traffic.

## Where verification happens

| Check | Evidence and boundary |
|---|---|
| `hostname` | Matches the expected DNS/IP identity against SANs. CN is informational. |
| `root_certificate` | Uses a separate verified handshake through Python's standard-library `ssl` module against the system or configured CA store, requiring the same leaf as the collected snapshot. |
| `chain` | Inspects the presented chain's structure and configured policy; does not verify signatures. |
| `pq_key_exchange` | Observes a group in a separate, unauthenticated probe; does not complete a TLS session. |

Revocation is not checked. CA issuer, OCSP, and CRL URLs in a certificate are reported as metadata rather than fetched. Configure private trust with `cafile` or `capath`; see [RootCertificate](validators/root_certificate.md).

## Keep the scanning policy explicit

Choose validators and their arguments for the environment you're monitoring. A PQ readiness failure and an expired certificate represent different findings. Keep `status`, `reason`, and `snapshot_at` in stored results so operational failures and stale observations remain visible.

Protocol detection, collection retries, trust verification, the optional PQ probe, and STARTTLS discovery on ports that refuse a TLS handshake can create additional connections. Set a suitable timeout and concurrency limit for your endpoints. See [Performance Tips](usage/performance.md) for a bounded scan example.

## Review security-tool exceptions

The repository configures Bandit in `.bandit` for intentional assessment behavior and uses `cargo audit` for Rust dependency advisories. The development report script also runs fixed shell commands. These exceptions need focused review when their code changes; they are not blanket permission to disable checks elsewhere.

```sh
make security
```

This runs both configured scanners. Review the findings alongside tests and code changes. The native parser uses Rust safety restrictions, corpus comparisons, and fuzzing, but those measures do not establish universal compatibility or prove the absence of bugs.

For contribution checks and the manual fuzzing workflow, see [Development](development.md) and the repository's [fuzzing guide](https://github.com/bradh11/certmonitor/blob/main/fuzz/README.md).
