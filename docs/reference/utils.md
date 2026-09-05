# API Reference: Utils

The `certmonitor.utils` package holds internal helpers shared by collection and validators. Its `identity` module normalizes SANs and matches DNS/IP identities; it is not a registered validator. Use [CertMonitor](certmonitor.md) for certificate retrieval and validation, or the [validator base classes](validators.md#base-classes) when extending the library.
