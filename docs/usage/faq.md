# FAQ

Got a quick question? Here are the ones that come up most often.

## Can I use CertMonitor with self-signed certificates?

Yes. Just keep in mind that some validators (like `root_certificate`) will report them as untrusted, since a self-signed certificate isn't chained to a trusted root. That's expected behavior, not a bug.

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
- The Rust-powered parsing releases the GIL while it runs, so CertMonitor is friendly to async code and threads, which makes large-scale or batch monitoring run with minimal overhead.

!!! note "The bottleneck is the network"
    For most checks, the dominant cost is network I/O, not parsing. So the best way to speed up a batch is to run more checks concurrently and let the network waits overlap.

## Is CertMonitor secure?

Security is a top priority. CertMonitor:

- Has zero third-party Python runtime dependencies.
- Uses secure defaults for all network and certificate operations.
- Is designed to be auditable, with a small, readable codebase.
- Relies on Rust for critical-path cryptography to minimize memory safety risks.

## Can I extend CertMonitor with custom validators?

Absolutely. CertMonitor is built to be extensible, so you can add your own validators to check for organization-specific requirements, compliance rules, or custom certificate properties. See the [Certificate Validators](../validators/index.md) section for details and examples.

## What platforms does CertMonitor support?

CertMonitor runs on any platform with Python 3.10+, with no third-party Python runtime dependencies. Pre-built wheels (which include the Rust components) are provided for major platforms where available. See the installation instructions for details.
