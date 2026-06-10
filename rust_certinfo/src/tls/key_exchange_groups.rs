// rust_certinfo/src/tls/key_exchange_groups.rs
//
// The TLS Supported Groups registry: which named group IDs CertMonitor
// recognizes in a TLS 1.3 key exchange, and how each is classified for
// post-quantum reporting. Self-contained data plus one lookup function,
// kept apart from the wire-format code — tracking new group codepoints
// never means touching parser logic.
//
// ## Which registry file do I touch?
//
// CertMonitor tracks the two distinct post-quantum surfaces in two
// independent data files — they are different namespaces (ASN.1 OIDs
// vs. 16-bit IANA codepoints) covering different algorithm families,
// so adding an entry to one NEVER requires touching the other:
//
//   - New **certificate** algorithm (signatures/keys: ML-DSA, SLH-DSA,
//     composites — published by NIST CSOR / IETF LAMPS)
//       → `rust_certinfo/src/pq_algorithms.rs`
//   - New **TLS key-exchange group** (KEMs: ML-KEM hybrids etc. —
//     published by the IANA TLS Supported Groups registry)
//       → this file
//
// ## Adding a group
//
// Append one entry to `SUPPORTED_GROUPS` with the values the IANA
// registry publishes — the numeric codepoint, the name, and a kind:
//
//     GroupInfo { id: 0x11EC, name: "X25519MLKEM768", kind: GroupKind::HybridPq },
//
// That is the whole job; `cargo test` checks the table (no duplicate
// ids or names). The same registry covers TLS 1.2 ECDHE
// (ServerKeyExchange.namedcurve) and TLS 1.3 (ServerHello.key_share) —
// only the wire location differs.
//
// ## Sources
//
//   - IANA "TLS Supported Groups" registry (the authority for every
//     codepoint below):
//     https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
//   - Hybrid ML-KEM groups (X25519MLKEM768, SecP256r1MLKEM768,
//     SecP384r1MLKEM1024): draft-kwiatkowski-tls-ecdhe-mlkem
//     https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/
//   - Pure ML-KEM groups: draft-connolly-tls-mlkem-key-agreement
//     https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement/
//   - X25519Kyber768Draft00 / SecP256r1Kyber768Draft00: pre-standard
//     hybrids (draft-tls-westerbaan-xyber768d00) still seen on long-tail
//     servers; classified hybrid_pq but named distinctly so reports show
//     the legacy deployment.

/// Classification of a named group for PQ reporting. String forms (the
/// Python-facing `kind` values) are produced by [`GroupKind::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// Classical elliptic-curve Diffie-Hellman — no PQ protection.
    ClassicalEcdh,
    /// Classical finite-field Diffie-Hellman — no PQ protection.
    ClassicalFfdh,
    /// Hybrid: classical + ML-KEM/Kyber combined. Counts as PQ.
    HybridPq,
    /// Pure post-quantum KEM.
    PurePq,
    /// Codepoint not in the table.
    Unknown,
}

impl GroupKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            GroupKind::ClassicalEcdh => "classical_ecdh",
            GroupKind::ClassicalFfdh => "classical_ffdh",
            GroupKind::HybridPq => "hybrid_pq",
            GroupKind::PurePq => "pure_pq",
            GroupKind::Unknown => "unknown",
        }
    }

    /// Hybrid counts as PQ (per the #28 architecture decision: requiring
    /// pure PQ today would fail every real-world deployment).
    pub fn is_pq(&self) -> bool {
        matches!(self, GroupKind::HybridPq | GroupKind::PurePq)
    }
}

/// One named group CertMonitor recognizes. See the module header for
/// how to add entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupInfo {
    /// IANA codepoint as it appears on the wire.
    pub id: u16,
    /// Registry name, reported verbatim to Python.
    pub name: &'static str,
    pub kind: GroupKind,
}

#[rustfmt::skip]
pub const SUPPORTED_GROUPS: &[GroupInfo] = &[
    // Classical elliptic curves (RFC 8446 / RFC 8422)
    GroupInfo { id: 0x0017, name: "secp256r1", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x0018, name: "secp384r1", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x0019, name: "secp521r1", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x001D, name: "x25519", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x001E, name: "x448", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x001F, name: "brainpoolP256r1tls13", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x0020, name: "brainpoolP384r1tls13", kind: GroupKind::ClassicalEcdh },
    GroupInfo { id: 0x0021, name: "brainpoolP512r1tls13", kind: GroupKind::ClassicalEcdh },
    // Classical finite-field DH (RFC 7919)
    GroupInfo { id: 0x0100, name: "ffdhe2048", kind: GroupKind::ClassicalFfdh },
    GroupInfo { id: 0x0101, name: "ffdhe3072", kind: GroupKind::ClassicalFfdh },
    GroupInfo { id: 0x0102, name: "ffdhe4096", kind: GroupKind::ClassicalFfdh },
    GroupInfo { id: 0x0103, name: "ffdhe6144", kind: GroupKind::ClassicalFfdh },
    GroupInfo { id: 0x0104, name: "ffdhe8192", kind: GroupKind::ClassicalFfdh },
    // Pure ML-KEM (draft-connolly-tls-mlkem-key-agreement)
    GroupInfo { id: 0x0200, name: "MLKEM512", kind: GroupKind::PurePq },
    GroupInfo { id: 0x0201, name: "MLKEM768", kind: GroupKind::PurePq },
    GroupInfo { id: 0x0202, name: "MLKEM1024", kind: GroupKind::PurePq },
    // Hybrid ML-KEM (draft-kwiatkowski-tls-ecdhe-mlkem)
    GroupInfo { id: 0x11EB, name: "SecP256r1MLKEM768", kind: GroupKind::HybridPq },
    GroupInfo { id: 0x11EC, name: "X25519MLKEM768", kind: GroupKind::HybridPq },
    GroupInfo { id: 0x11ED, name: "SecP384r1MLKEM1024", kind: GroupKind::HybridPq },
    // Legacy pre-standard Kyber hybrids (xyber768d00)
    GroupInfo { id: 0x6399, name: "X25519Kyber768Draft00", kind: GroupKind::HybridPq },
    GroupInfo { id: 0x639A, name: "SecP256r1Kyber768Draft00", kind: GroupKind::HybridPq },
];

/// Look up a group by its IANA codepoint.
pub fn lookup(id: u16) -> Option<&'static GroupInfo> {
    SUPPORTED_GROUPS.iter().find(|g| g.id == id)
}

/// Classify a codepoint, falling back to `Unknown` for anything not in
/// the table.
pub fn kind_of(id: u16) -> GroupKind {
    lookup(id).map(|g| g.kind).unwrap_or(GroupKind::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_no_duplicates() {
        use std::collections::HashSet;
        let mut ids: HashSet<u16> = HashSet::new();
        let mut names: HashSet<&str> = HashSet::new();
        for g in SUPPORTED_GROUPS {
            assert!(ids.insert(g.id), "duplicate id {:#06x}", g.id);
            assert!(names.insert(g.name), "duplicate name {}", g.name);
        }
    }

    #[test]
    fn known_classifications() {
        assert_eq!(lookup(0x001D).unwrap().name, "x25519");
        assert!(!kind_of(0x001D).is_pq());
        assert_eq!(kind_of(0x0100), GroupKind::ClassicalFfdh);

        let hybrid = lookup(0x11EC).unwrap();
        assert_eq!(hybrid.name, "X25519MLKEM768");
        assert_eq!(hybrid.kind, GroupKind::HybridPq);
        assert!(hybrid.kind.is_pq());

        assert_eq!(kind_of(0x0201), GroupKind::PurePq);
        assert!(kind_of(0x0201).is_pq());

        // Legacy draft hybrids count as PQ but keep their draft name.
        assert_eq!(lookup(0x6399).unwrap().name, "X25519Kyber768Draft00");
        assert!(kind_of(0x6399).is_pq());
    }

    #[test]
    fn unknown_codepoint_is_unknown() {
        assert!(lookup(0x4242).is_none());
        assert_eq!(kind_of(0x4242), GroupKind::Unknown);
        assert_eq!(kind_of(0x4242).as_str(), "unknown");
        assert!(!kind_of(0x4242).is_pq());
    }

    #[test]
    fn kind_strings_are_stable() {
        // These strings are (future) Python-facing API via the probe.
        assert_eq!(GroupKind::ClassicalEcdh.as_str(), "classical_ecdh");
        assert_eq!(GroupKind::ClassicalFfdh.as_str(), "classical_ffdh");
        assert_eq!(GroupKind::HybridPq.as_str(), "hybrid_pq");
        assert_eq!(GroupKind::PurePq.as_str(), "pure_pq");
    }
}
