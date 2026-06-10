// rust_certinfo/src/tls/mlkem_kat.rs
//
// A real, structurally valid ML-KEM-768 encapsulation key, used as the
// ML-KEM half of the probe's X25519MLKEM768 key_share. The probe never
// performs any ML-KEM operation — it sends this key, reads the
// ServerHello, and hangs up — but the bytes must be a VALID FIPS 203
// encapsulation key, because servers modulus-check the key before
// replying (an invalid one draws a handshake_failure alert instead of a
// ServerHello; see the live smoke test on issue #33).
//
// The key is opaque lattice key material — 768 packed coefficients plus
// a 32-byte seed — so unlike the OID and group tables it cannot be
// derived from a human-readable form; the only shorter representation is
// a 32-byte seed expanded by a full ML-KEM keygen (SHAKE + NTT), which
// would mean taking on the crypto dependency this crate deliberately
// avoids. So the bytes ARE the source of truth. To keep them out of the
// source as readable-but-meaningless hex, they live in a sibling binary
// fixture and are embedded with `include_bytes!` — the same way the repo
// stores its DER test fixtures. A wrong-sized file fails the build.
//
// Provenance / regeneration: NIST ACVP-Server ML-KEM-keyGen-FIPS203
// known-answer test vectors, parameterSet "ML-KEM-768", tcId 26, from
// https://github.com/usnistgov/ACVP-Server. Regenerate the fixture with
// `python scripts/fetch_mlkem_kat.py` (documented there). This is a
// PUBLIC key with no secret counterpart in the tree; it carries no
// security value beyond "looks like a real client share".

/// ML-KEM-768 encapsulation key (FIPS 203), 1184 bytes. Embedded from a
/// binary fixture; the `[u8; 1184]` type makes a wrong-length fixture a
/// compile error.
pub const MLKEM768_KAT_EK: [u8; 1184] = *include_bytes!("mlkem768_kat_ek.bin");

#[cfg(test)]
mod mlkem_kat_tests {
    use super::MLKEM768_KAT_EK;

    /// Decode one 384-byte block into 256 twelve-bit coefficients
    /// (FIPS 203 ByteDecode_12).
    fn decode12(block: &[u8]) -> Vec<u16> {
        let mut out = Vec::with_capacity(256);
        for c in block.chunks_exact(3) {
            let x = u32::from(c[0]) | u32::from(c[1]) << 8 | u32::from(c[2]) << 16;
            out.push((x & 0xFFF) as u16);
            out.push(((x >> 12) & 0xFFF) as u16);
        }
        out
    }

    #[test]
    fn kat_ek_is_valid_fips203_encapsulation_key() {
        // ML-KEM-768 ek = 3 packed polynomials (3 * 384 = 1152 bytes) + 32-byte rho.
        assert_eq!(MLKEM768_KAT_EK.len(), 1184);
        let body = &MLKEM768_KAT_EK[..1152];
        let coeffs: Vec<u16> = body.chunks_exact(384).flat_map(decode12).collect();
        assert_eq!(coeffs.len(), 768);
        // The modulus check a server applies before replying: every
        // coefficient must be reduced mod q = 3329.
        assert!(
            coeffs.iter().all(|&c| c < 3329),
            "ek has an out-of-range coefficient — not a valid FIPS 203 key"
        );
    }
}
