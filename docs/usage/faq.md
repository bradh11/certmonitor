# FAQ

Got a quick question? Here are the ones that come up most often.

## Can I use CertMonitor with self-signed certificates?

Yes. Collection can inspect self-signed certificates. `root_certificate` passes only if the configured trust store accepts the certificate; for your private PKI, pass a suitable `cafile` or `capath`. Being self-signed does not automatically establish trust. See [RootCertificate](../validators/root_certificate.md).

## How do I see all available validators?

Ask CertMonitor directly:

```python
from certmonitor.validators import list_validators
print(list_validators())
```

!!! info "Which validators run by default?"
    Three validators are enabled out of the box: `expiration`, `hostname`, and `root_certificate`. Every other validator is opt-in, so you turn it on when you need it.

## How do I debug certificate parsing errors?

When something goes wrong, CertMonitor hands back a structured error rather than raising. Check the error message in the returned dictionary, and try a different host or port to narrow down the cause.

## Why does CertMonitor have no third-party Python runtime dependencies?

It's a deliberate choice for portability, security, and maintainability. The orchestration and logic are pure Python, while the heavy lifting of certificate parsing and elliptic curve support is powered by Rust bindings. Leaning on Rust for those critical operations gives you speed, safety, and correctness, all without pulling in third-party Python packages.

## How does CertMonitor handle advanced cryptography and certificate parsing?

Certificate parsing and public key handling, including elliptic curve support, run through Rust bindings. That's where the speed and safety come from, while the core tool stays lightweight and free of third-party Python dependencies for its orchestration and logic.

## How does CertMonitor ensure high performance?

CertMonitor is built for speed and concurrency:

- Network and certificate operations are designed to be fast.
- The API supports asynchronous and parallel workflows (see the [Performance Tips](performance.md) page for examples).
- Use one monitor per worker to overlap network waits. The API is synchronous; `asyncio.to_thread()` keeps it off an async event loop. The Rust TLS probe releases the GIL during probing, but the certificate parser does not promise that.

!!! note "The bottleneck is the network"
    For most checks, the dominant cost is network I/O, not parsing. So the best way to speed up a batch is to run more checks concurrently and let the network waits overlap.

## Is CertMonitor secure?

Security is a top priority. CertMonitor:

- Has zero third-party Python runtime dependencies.
- Collects certificates permissively so you can inspect broken endpoints, then reports trust through a separate verified handshake. Read the validator results; successful collection alone is not a security verdict.
- Is designed to be auditable, with a small, readable codebase.
- Uses Rust for certificate parsing and Python's OpenSSL-backed `ssl` module for TLS and trust verification. Revocation checks are not implemented.

## Can I extend CertMonitor with custom validators?

Absolutely. CertMonitor is built to be extensible, so you can add your own validators to check for organization-specific requirements, compliance rules, or custom certificate properties. See the [Certificate Validators](../validators/index.md) section for details and examples.

## What platforms does CertMonitor support?

CertMonitor is zero-dependency: the package accepts Python 3.10 to 3.15 with no third-party Python runtime dependencies. It requires its native extension, which ships inside the wheel. Use a matching wheel where available, or install Rust to build from source. See [Installation](installation.md) for the requirements and release-specific wheel availability.
