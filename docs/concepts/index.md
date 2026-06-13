# Concepts

Background on the cryptography CertMonitor inspects — useful whether you're new to TLS or brushing up before a post-quantum migration. These pages are vendor-neutral explainers; the [Validators](../validators/index.md) section shows how CertMonitor measures each thing in practice.

- **[How TLS & HTTPS Work](how-tls-works.md)** — what the handshake does, where certificates fit, and the difference between key exchange and signatures (with a handshake diagram).
- **[Certificates & PKI](certificates-and-pki.md)** — what's inside an X.509 certificate, the chain of trust, and how certificates are issued (with chain and issuance diagrams).
- **[Post-Quantum Cryptography](post-quantum.md)** — the quantum threat, *harvest-now-decrypt-later*, the NIST standards (ML-KEM / ML-DSA / SLH-DSA), hybrids, and the migration challenges.

New to all of this? Read them in order. Already fluent and here for the quantum-safe story? Jump straight to [Post-Quantum Cryptography](post-quantum.md).
