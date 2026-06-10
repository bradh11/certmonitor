// rust_certinfo/src/pq_algorithms.rs
//
// The post-quantum **certificate algorithm** registry. This file is
// deliberately self-contained — pure data plus one lookup function —
// and kept apart from the DER / X.509 parser code so that tracking the
// PQ ecosystem never means touching parser logic.
//
// ## Which registry file do I touch?
//
// This file covers algorithms that appear *inside certificates*
// (signature/key OIDs from NIST CSOR / IETF LAMPS). TLS *key-exchange
// groups* (ML-KEM hybrids etc., 16-bit IANA codepoints seen in
// handshakes) live in their own independent registry at
// `rust_certinfo/src/tls/groups.rs` — different namespace, different
// algorithm families, so adding an entry to one never requires
// touching the other.
//
// ## Adding an algorithm
//
// Append one entry to `PQ_ALGORITHMS` with the two values the source
// registry publishes — the dotted-decimal OID and the algorithm name:
//
//     PqAlgorithm {
//         dotted: "2.16.840.1.101.3.4.3.17",
//         name: "ml-dsa-44",
//         composite: false,
//     },
//
// That is the whole job: the SPKI parser and the chain analysis pick the
// entry up automatically, and `cargo test` checks the table (the dotted
// form is well-formed, there are no duplicate OIDs or names, and every
// entry is findable from its wire encoding).
//
// `composite` distinguishes the two kinds of PQ algorithm OIDs in the
// wild: `false` for a standalone PQ algorithm (ML-DSA, SLH-DSA), `true`
// for a hybrid "composite" — a single OID that stands for a PQ and a
// classical algorithm used together (e.g. ML-DSA-65 + ECDSA P-256), the
// transitional form CAs use while classical crypto is still trusted.
//
// ## Sources (every OID below is copy-checkable against these)
//
//   - NIST CSOR algorithm registry (the authority for the sigAlgs arc
//     2.16.840.1.101.3.4.3 used by ML-DSA and SLH-DSA):
//     https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
//   - ML-DSA (FIPS 204, https://csrc.nist.gov/pubs/fips/204/final):
//     X.509 algorithm identifiers per RFC 9881 §3
//     (https://www.rfc-editor.org/rfc/rfc9881.html) — sigAlgs .17/.18/.19.
//   - SLH-DSA (FIPS 205, https://csrc.nist.gov/pubs/fips/205/final):
//     X.509 algorithm identifiers per RFC 9909
//     (https://www.rfc-editor.org/rfc/rfc9909.html) — sigAlgs .20–.31,
//     ordered sha2-128s/f, 192s/f, 256s/f, then shake-128s/f, 192s/f, 256s/f.
//   - Composite ML-DSA: draft-ietf-lamps-pq-composite-sigs-19
//     (https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/),
//     name→OID table maintained at
//     https://github.com/lamps-wg/draft-composite-sigs/blob/main/src/algParams.md
//     — IANA-assigned PKIX arc 1.3.6.1.5.5.7.6.37–.54. NOTE: drafts ≤ -12
//     used Entrust's prototyping arc 2.16.840.1.114027.80.8.1; those
//     codepoints were abandoned and are intentionally NOT listed. If the
//     draft renumbers again before RFC, this file is the only place to
//     update.
//   - Falcon / FN-DSA (future FIPS 206): no stable OID codepoints as of
//     June 2026. TODO: add once NIST CSOR assigns them.
//
// These OIDs identify both the SubjectPublicKeyInfo algorithm and the
// certificate signatureAlgorithm — ML-DSA/SLH-DSA use the same OID for
// the key and the signature, with absent parameters.
//
// ## How matching works
//
// Certificates carry OIDs DER-encoded (X.690 §8.19), not as dotted
// strings. `lookup` turns the wire bytes back into dotted-decimal using
// the same `der::Oid` decoder the parser uses everywhere, then compares
// against `dotted` — so this file only ever stores the human-readable
// form, and no contributor ever encodes anything by hand.

use crate::der::Oid;

/// One post-quantum algorithm CertMonitor recognizes. See the module
/// header for how to add entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqAlgorithm {
    /// Dotted-decimal OID exactly as published in the source registry.
    pub dotted: &'static str,
    /// Python-facing lowercase name (the `algorithm` dict field).
    pub name: &'static str,
    /// `true` for hybrid composite signatures — one OID standing for a
    /// PQ and a classical algorithm used together. `false` for a
    /// standalone PQ algorithm.
    pub composite: bool,
}

#[rustfmt::skip]
pub const PQ_ALGORITHMS: &[PqAlgorithm] = &[
    // ML-DSA (FIPS 204) — RFC 9881 §3: https://www.rfc-editor.org/rfc/rfc9881.html
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.17", name: "ml-dsa-44", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.18", name: "ml-dsa-65", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.19", name: "ml-dsa-87", composite: false },
    // SLH-DSA (FIPS 205) — all twelve parameter sets, RFC 9909:
    // https://www.rfc-editor.org/rfc/rfc9909.html
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.20", name: "slh-dsa-sha2-128s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.21", name: "slh-dsa-sha2-128f", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.22", name: "slh-dsa-sha2-192s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.23", name: "slh-dsa-sha2-192f", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.24", name: "slh-dsa-sha2-256s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.25", name: "slh-dsa-sha2-256f", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.26", name: "slh-dsa-shake-128s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.27", name: "slh-dsa-shake-128f", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.28", name: "slh-dsa-shake-192s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.29", name: "slh-dsa-shake-192f", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.30", name: "slh-dsa-shake-256s", composite: false },
    PqAlgorithm { dotted: "2.16.840.1.101.3.4.3.31", name: "slh-dsa-shake-256f", composite: false },
    // Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-19) — name→OID table:
    // https://github.com/lamps-wg/draft-composite-sigs/blob/main/src/algParams.md
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.37", name: "mldsa44-rsa2048-pss-sha256", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.38", name: "mldsa44-rsa2048-pkcs15-sha256", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.39", name: "mldsa44-ed25519-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.40", name: "mldsa44-ecdsa-p256-sha256", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.41", name: "mldsa65-rsa3072-pss-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.42", name: "mldsa65-rsa3072-pkcs15-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.43", name: "mldsa65-rsa4096-pss-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.44", name: "mldsa65-rsa4096-pkcs15-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.45", name: "mldsa65-ecdsa-p256-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.46", name: "mldsa65-ecdsa-p384-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.47", name: "mldsa65-ecdsa-brainpoolp256r1-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.48", name: "mldsa65-ed25519-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.49", name: "mldsa87-ecdsa-p384-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.50", name: "mldsa87-ecdsa-brainpoolp384r1-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.51", name: "mldsa87-ed448-shake256", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.52", name: "mldsa87-rsa3072-pss-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.53", name: "mldsa87-rsa4096-pss-sha512", composite: true },
    PqAlgorithm { dotted: "1.3.6.1.5.5.7.6.54", name: "mldsa87-ecdsa-p521-sha512", composite: true },
];

/// Look up a recognized PQ algorithm by its decoded OID.
pub fn lookup(oid: Oid<'_>) -> Option<&'static PqAlgorithm> {
    let dotted = oid.to_id_string();
    PQ_ALGORITHMS.iter().find(|alg| alg.dotted == dotted)
}

/// DER-encode a dotted-decimal OID (X.690 §8.19). Test-only: lets tests
/// derive wire bytes for table entries (here and in `x509::spki`) without
/// hand-written hex. Cross-checked against the hand-written classic
/// constants in `der::oid`, which are an independent fixed point.
#[cfg(test)]
pub(crate) fn encode_dotted_for_tests(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| a.parse().expect("dotted OID arcs must be numeric"))
        .collect();
    assert!(arcs.len() >= 2, "OID needs at least two arcs: {}", dotted);
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        // Base-128, big-endian, continuation bit on all but the last byte.
        let mut groups = [0u8; 10];
        let mut i = groups.len();
        let mut v = arc;
        loop {
            i -= 1;
            groups[i] = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        let last = groups.len() - 1;
        for (j, b) in groups.iter().enumerate().skip(i) {
            out.push(if j == last { *b } else { b | 0x80 });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::oid::{OID_EC_PUBLIC_KEY, OID_EXT_SKI, OID_RSA_ENCRYPTION, OID_SECP384R1};

    #[test]
    fn table_is_well_formed_and_unique() {
        use std::collections::HashSet;
        let mut dotteds: HashSet<&str> = HashSet::new();
        let mut names: HashSet<&str> = HashSet::new();
        for alg in PQ_ALGORITHMS {
            let arcs: Vec<u64> = alg
                .dotted
                .split('.')
                .map(|a| {
                    a.parse().unwrap_or_else(|_| {
                        panic!(
                            "{}: dotted form {:?} has a non-numeric arc",
                            alg.name, alg.dotted
                        )
                    })
                })
                .collect();
            assert!(arcs.len() >= 3, "{}: dotted form too short", alg.name);
            assert!(arcs[0] <= 2, "{}: first arc must be 0, 1, or 2", alg.name);
            assert!(
                !alg.name.is_empty() && alg.name == alg.name.to_lowercase(),
                "{}: names must be lowercase",
                alg.name
            );
            assert!(dotteds.insert(alg.dotted), "duplicate OID {}", alg.dotted);
            assert!(names.insert(alg.name), "duplicate name {}", alg.name);
        }
        // 3 ML-DSA + 12 SLH-DSA + 18 composite ML-DSA
        assert_eq!(PQ_ALGORITHMS.len(), 33);
    }

    #[test]
    fn every_entry_is_found_from_its_wire_encoding() {
        for alg in PQ_ALGORITHMS {
            let wire = encode_dotted_for_tests(alg.dotted);
            let oid = Oid::from_bytes(&wire).unwrap();
            let found = lookup(oid)
                .unwrap_or_else(|| panic!("{} not found from its own wire bytes", alg.name));
            assert_eq!(found.name, alg.name);
        }
    }

    #[test]
    fn test_encoder_agrees_with_classic_constants() {
        // The hand-written constants in der::oid long predate this file
        // and serve as an independent fixed point for the test encoder.
        assert_eq!(
            encode_dotted_for_tests("1.2.840.113549.1.1.1"),
            OID_RSA_ENCRYPTION
        );
        assert_eq!(
            encode_dotted_for_tests("1.2.840.10045.2.1"),
            OID_EC_PUBLIC_KEY
        );
        assert_eq!(encode_dotted_for_tests("1.3.132.0.34"), OID_SECP384R1);
        assert_eq!(encode_dotted_for_tests("2.5.29.14"), OID_EXT_SKI);
    }

    #[test]
    fn pinned_wire_bytes() {
        // Intentional hex: pins the exact wire bytes for one entry per
        // OID arc, independent of both the encoder and the decoder, so a
        // shared bug cannot silently shift what the parser matches.
        let ml = Oid::from_bytes(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]).unwrap();
        assert_eq!(lookup(ml).unwrap().name, "ml-dsa-65");
        assert!(!lookup(ml).unwrap().composite);

        let comp = Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x25]).unwrap();
        let info = lookup(comp).unwrap();
        assert_eq!(info.name, "mldsa44-rsa2048-pss-sha256");
        assert!(info.composite);

        // Classical algorithms are not PQ.
        assert!(lookup(Oid::from_bytes(OID_RSA_ENCRYPTION).unwrap()).is_none());
        assert!(lookup(Oid::from_bytes(OID_EC_PUBLIC_KEY).unwrap()).is_none());
    }
}
