# Validators Overview

CertMonitor provides a modular validator system to check various aspects of SSL/TLS certificates and connections. Each validator can be enabled or disabled as needed, and some accept additional arguments for fine-grained control.

Available validators:

- [Expiration](expiration.md): Checks if the certificate is expired or expiring soon.
- [Hostname](hostname.md): Validates that the certificate matches the expected hostname.
- [SubjectAltNames](subject_alt_names.md): Checks the Subject Alternative Names (SANs) extension.
- [RootCertificate](root_certificate.md): Checks if the certificate is issued by a trusted root CA.
- [KeyInfo](key_info.md): Validates the public key type and strength.
- [TLSVersion](tls_version.md): Validates the negotiated TLS version.
- [WeakCipher](weak_cipher.md): Validates that the negotiated cipher suite is in the allowed list.
- [SensitiveDate](sensitive_date.md): Validates that the certificate doesn't expire on built-in or user specified sensitive dates.

See each page for usage and output examples.

---

<!-- Individual validator API documentation is now only in their respective pages to avoid mkdocs_autorefs duplicate anchor warnings. -->
