// rust_certinfo/src/x509/spki.rs
//
// SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm        AlgorithmIdentifier,
//     subjectPublicKey BIT STRING
// }
//
// Two key types matter for the public web today: RSA and EC. For RSA we
// extract the modulus bit length from the inner SubjectPublicKey contents,
// under rsaEncryption or under id-RSASSA-PSS (RFC 4055 §1.2), which names
// the same RSAPublicKey but restricts the key to RSASSA-PSS signatures
// (RFC 4055 §3.3).
// For EC the curve OID lives in `algorithm.parameters`, the algorithm
// OID itself is always id-ecPublicKey, never the curve. Post-quantum
// algorithms (ML-DSA, SLH-DSA, composite ML-DSA) are recognized via the
// registry in `crate::pq_algorithms`, for those the OID alone
// identifies the parameter set, and we report the subjectPublicKey bit
// length as `key_bits`. Ed25519 and Ed448 (RFC 8410) are likewise
// identified by OID alone, each has exactly one parameter set. Anything
// else collapses to `Unknown`.

use crate::der::{oid, tag, DerReader, Oid};
use crate::error::ParseError;
use crate::pq_algorithms;
use crate::x509::algorithm::AlgorithmIdentifier;

#[derive(Debug, Clone, Copy)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    /// BIT STRING contents *after* the unused-bits prefix byte. For RSA
    /// this wraps `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
    /// For EC this is the raw EC point.
    pub subject_public_key: &'a [u8],
    /// Outer SubjectPublicKeyInfo TLV including the SEQUENCE tag and
    /// length prefix. This is what `extract_public_key_der` returns.
    pub raw: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum PublicKeyAlgorithm<'a> {
    Rsa {
        modulus_bits: usize,
        /// True when the key's algorithm OID is id-RSASSA-PSS rather than
        /// rsaEncryption (RFC 4055 §1.2). RFC 4055 §3.3 restricts such a
        /// key to RSASSA-PSS signatures, so callers refuse PKCS#1 v1.5
        /// under it.
        pss_only: bool,
    },
    Ec {
        curve_oid: Oid<'a>,
        key_bits: usize,
    },
    /// Post-quantum algorithm from the `crate::pq_algorithms` registry.
    /// The OID alone identifies the parameter set (no parameters, no
    /// curve), so strength is judged by algorithm identity, `key_bits`
    /// is the raw subjectPublicKey bit length, reported for information
    /// only (e.g. ML-DSA-65 → 15616).
    PostQuantum {
        algorithm: &'static pq_algorithms::PqAlgorithm,
        key_bits: usize,
    },
    /// Ed25519 or Ed448 (RFC 8410). Strength is fixed by the algorithm;
    /// `key_bits` is the raw subjectPublicKey bit length for information.
    EdDsa {
        name: &'static str,
        key_bits: usize,
    },
    Unknown,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// Parse a SubjectPublicKeyInfo from a sub-reader positioned at its
    /// outer SEQUENCE tag. Captures the raw outer TLV slice for later
    /// retrieval via `extract_public_key_der`.
    pub fn parse(reader: &mut DerReader<'a>) -> Result<Self, ParseError> {
        let tlv = reader.read_tlv()?;
        if tlv.tag != tag::TAG_SEQUENCE {
            return Err(ParseError::UnexpectedTag {
                expected: tag::TAG_SEQUENCE,
                got: tlv.tag,
            });
        }
        let raw = tlv.raw;
        let mut inner = DerReader::new(tlv.value);
        let algorithm = AlgorithmIdentifier::parse(&mut inner)?;

        let bit_string_value = inner.expect(tag::TAG_BIT_STRING)?;
        if bit_string_value.is_empty() {
            return Err(ParseError::InvalidBitString);
        }
        // First byte of a BIT STRING is the count of unused trailing bits;
        // for SPKI it's always 0.
        if bit_string_value[0] != 0 {
            return Err(ParseError::InvalidBitString);
        }
        let subject_public_key = &bit_string_value[1..];

        inner.end()?;
        Ok(Self {
            algorithm,
            subject_public_key,
            raw,
        })
    }

    pub fn parsed(&self) -> PublicKeyAlgorithm<'a> {
        let alg_bytes = self.algorithm.algorithm.as_bytes();
        if alg_bytes == oid::OID_RSA_ENCRYPTION {
            return parse_rsa(self.subject_public_key, false);
        }
        // RFC 4055 §1.2: an RSA public key may name id-RSASSA-PSS as its
        // algorithm, optionally with `RSASSA-PSS-params`. The
        // subjectPublicKey is the same RSAPublicKey either way; what
        // changes is that RFC 4055 §3.3 restricts the key to RSASSA-PSS
        // signatures, which `pss_only` carries to the callers.
        if alg_bytes == oid::OID_RSASSA_PSS {
            return parse_rsa(self.subject_public_key, true);
        }
        if alg_bytes == oid::OID_EC_PUBLIC_KEY {
            return parse_ec(self);
        }
        // RFC 8410 §3 fixes the key length for each curve: 32 bytes for
        // Ed25519, 57 for Ed448. A key of any other length under one of
        // these OIDs is malformed, so it falls to `Unknown` rather than
        // being reported as EdDSA with a length no `key_info` check
        // written against RFC 8410 would expect.
        if alg_bytes == oid::OID_ED25519 {
            return if self.subject_public_key.len() == 32 {
                PublicKeyAlgorithm::EdDsa {
                    name: "Ed25519",
                    key_bits: self.subject_public_key.len() * 8,
                }
            } else {
                PublicKeyAlgorithm::Unknown
            };
        }
        if alg_bytes == oid::OID_ED448 {
            return if self.subject_public_key.len() == 57 {
                PublicKeyAlgorithm::EdDsa {
                    name: "Ed448",
                    key_bits: self.subject_public_key.len() * 8,
                }
            } else {
                PublicKeyAlgorithm::Unknown
            };
        }
        if let Some(algorithm) = pq_algorithms::lookup(self.algorithm.algorithm) {
            return PublicKeyAlgorithm::PostQuantum {
                algorithm,
                key_bits: self.subject_public_key.len() * 8,
            };
        }
        PublicKeyAlgorithm::Unknown
    }
}

/// RSA SubjectPublicKey: `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
/// We report the modulus's true bit length: DER's sign byte is stripped
/// and leading zero bits are subtracted. `pss_only` is set by the caller
/// from the algorithm OID, id-RSASSA-PSS keys carry it (RFC 4055 §3.3).
fn parse_rsa(subject_public_key: &[u8], pss_only: bool) -> PublicKeyAlgorithm<'static> {
    let mut r = DerReader::new(subject_public_key);
    let inner = match r.expect_constructed(tag::TAG_SEQUENCE) {
        Ok(s) => s,
        Err(_) => return PublicKeyAlgorithm::Unknown,
    };
    let mut inner = inner;
    let modulus = match inner.expect(tag::TAG_INTEGER) {
        Ok(v) => v,
        Err(_) => return PublicKeyAlgorithm::Unknown,
    };
    // DER unsigned integers prepend 0x00 when the high bit is set; strip
    // that byte, then count the leading zero bits of what remains so a
    // 2041-bit modulus is reported as 2041, not rounded up to 2048. A
    // leading zero byte that is not followed by a high bit is not minimal
    // DER, and a value that starts with 0x00 after stripping is malformed.
    let trimmed = if modulus.len() > 1 && modulus[0] == 0x00 && modulus[1] & 0x80 != 0 {
        &modulus[1..]
    } else {
        modulus
    };
    let modulus_bits = match trimmed.first() {
        None | Some(0) => return PublicKeyAlgorithm::Unknown,
        Some(&first) => trimmed.len() * 8 - first.leading_zeros() as usize,
    };
    PublicKeyAlgorithm::Rsa {
        modulus_bits,
        pss_only,
    }
}

/// EC SubjectPublicKey:
///   - `algorithm.parameters` is an ECParameters CHOICE; in practice it's
///     always a named-curve OID.
///   - `subjectPublicKey` is the encoded point (uncompressed `0x04 || X || Y`,
///     or compressed `0x02 / 0x03 || X`).
fn parse_ec<'a>(spki: &SubjectPublicKeyInfo<'a>) -> PublicKeyAlgorithm<'a> {
    let curve_oid = match spki.algorithm.parameters {
        Some(raw) => match parse_oid_tlv(raw) {
            Some(o) => o,
            None => return PublicKeyAlgorithm::Unknown,
        },
        None => return PublicKeyAlgorithm::Unknown,
    };
    let key_bits = ec_key_bits(curve_oid, spki.subject_public_key);
    PublicKeyAlgorithm::Ec {
        curve_oid,
        key_bits,
    }
}

/// Extract an `Oid` from a raw OID TLV (tag + length + value).
fn parse_oid_tlv(raw: &[u8]) -> Option<Oid<'_>> {
    let mut r = DerReader::new(raw);
    let value = r.expect(tag::TAG_OBJECT_IDENTIFIER).ok()?;
    Oid::from_bytes(value).ok()
}

/// Map a curve OID to its field bit length, or fall back to computing it
/// from the EC point byte length when the curve is not in our table.
/// Uncompressed point: `0x04 || X || Y` → field bytes = (len - 1) / 2.
/// Compressed point:   `0x02 / 0x03 || X` → field bytes = len - 1.
fn ec_key_bits(curve_oid: Oid<'_>, subject_public_key: &[u8]) -> usize {
    let bytes = curve_oid.as_bytes();
    if bytes == oid::OID_SECP256R1 {
        return 256;
    }
    if bytes == oid::OID_SECP384R1 {
        return 384;
    }
    if bytes == oid::OID_SECP521R1 {
        return 521;
    }
    if bytes == oid::OID_SECP256K1 {
        return 256;
    }
    // Fallback: derive from the raw point.
    if subject_public_key.is_empty() {
        return 0;
    }
    let leading = subject_public_key[0];
    let payload = &subject_public_key[1..];
    let field_bytes = match leading {
        0x04 => payload.len() / 2,
        0x02 | 0x03 => payload.len(),
        _ => return 0,
    };
    field_bytes * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SPKI for RSA-2048 with a modulus whose top bit is
    /// set, which is why DER's sign byte (0x00) precedes it.
    fn rsa_2048_spki() -> Vec<u8> {
        // RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
        // modulus: 257 bytes (0x00 || 0x80 || 255 zero bytes) so the
        // trimmed length is 256 bytes = 2048 bits.
        let mut modulus = vec![0x00u8, 0x80u8];
        modulus.extend(vec![0u8; 255]);
        // SEQUENCE { INTEGER modulus, INTEGER publicExponent }
        let mut rsa_pk = vec![
            tag::TAG_INTEGER,
            0x82,
            ((modulus.len() >> 8) & 0xff) as u8,
            (modulus.len() & 0xff) as u8,
        ];
        rsa_pk.extend(&modulus);
        // INTEGER publicExponent (0x010001 = 65537)
        rsa_pk.extend(&[tag::TAG_INTEGER, 0x03, 0x01, 0x00, 0x01]);

        let mut sequence = vec![
            tag::TAG_SEQUENCE,
            0x82,
            ((rsa_pk.len() >> 8) & 0xff) as u8,
            (rsa_pk.len() & 0xff) as u8,
        ];
        sequence.extend(&rsa_pk);

        // BIT STRING wrapper: unused-bits byte + RSA SEQUENCE
        let mut bit_string = vec![tag::TAG_BIT_STRING];
        let bs_len = sequence.len() + 1;
        bit_string.push(0x82);
        bit_string.push(((bs_len >> 8) & 0xff) as u8);
        bit_string.push((bs_len & 0xff) as u8);
        bit_string.push(0x00); // unused bits
        bit_string.extend(&sequence);

        // AlgorithmIdentifier { OID rsaEncryption, NULL }
        let alg_bytes = oid::OID_RSA_ENCRYPTION;
        let mut alg = vec![tag::TAG_SEQUENCE, 0x0d];
        alg.push(tag::TAG_OBJECT_IDENTIFIER);
        alg.push(alg_bytes.len() as u8);
        alg.extend(alg_bytes);
        alg.extend(&[tag::TAG_NULL, 0x00]);

        // Outer SubjectPublicKeyInfo SEQUENCE
        let inner_len = alg.len() + bit_string.len();
        let mut spki = vec![tag::TAG_SEQUENCE, 0x82];
        spki.push(((inner_len >> 8) & 0xff) as u8);
        spki.push((inner_len & 0xff) as u8);
        spki.extend(&alg);
        spki.extend(&bit_string);
        spki
    }

    #[test]
    fn rsa_modulus_bit_length() {
        let bytes = rsa_2048_spki();
        let mut r = DerReader::new(&bytes);
        let spki = SubjectPublicKeyInfo::parse(&mut r).unwrap();
        match spki.parsed() {
            PublicKeyAlgorithm::Rsa { modulus_bits, .. } => assert_eq!(modulus_bits, 2048),
            other => panic!("expected RSA, got {:?}", other),
        }
    }

    /// Minimal DER length encoding (short and long form) for test builders.
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
        }
    }

    fn der_tlv(tag_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag_byte];
        out.extend(der_len(body.len()));
        out.extend(body);
        out
    }

    /// Build a minimal SPKI: `AlgorithmIdentifier { OID, no parameters }`
    /// followed by a BIT STRING wrapping `key_len` zero bytes. This is
    /// the shape ML-DSA / SLH-DSA / composite keys use, absent parameters.
    fn synthetic_spki(alg_oid: &[u8], key_len: usize) -> Vec<u8> {
        let alg = der_tlv(
            tag::TAG_SEQUENCE,
            &der_tlv(tag::TAG_OBJECT_IDENTIFIER, alg_oid),
        );
        let mut bs_body = vec![0x00]; // unused-bits byte
        bs_body.extend(vec![0u8; key_len]);
        let bit_string = der_tlv(tag::TAG_BIT_STRING, &bs_body);
        let mut body = alg;
        body.extend(bit_string);
        der_tlv(tag::TAG_SEQUENCE, &body)
    }

    fn parse_spki(bytes: &[u8]) -> PublicKeyAlgorithm<'_> {
        let mut r = DerReader::new(bytes);
        let spki = SubjectPublicKeyInfo::parse(&mut r).unwrap();
        spki.parsed()
    }

    #[test]
    fn ml_dsa_65_parses_with_key_bits() {
        // ML-DSA-65 public keys are 1952 bytes (FIPS 204 table 2).
        let ml_dsa_65 = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
        let bytes = synthetic_spki(ml_dsa_65, 1952);
        match parse_spki(&bytes) {
            PublicKeyAlgorithm::PostQuantum {
                algorithm,
                key_bits,
            } => {
                assert_eq!(algorithm.name, "ml-dsa-65");
                assert!(!algorithm.composite);
                assert_eq!(key_bits, 1952 * 8);
            }
            other => panic!("expected PostQuantum, got {:?}", other),
        }
    }

    #[test]
    fn slh_dsa_sha2_128s_parses() {
        // SLH-DSA-SHA2-128s public keys are 32 bytes (FIPS 205 table 2).
        let slh = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14];
        let bytes = synthetic_spki(slh, 32);
        match parse_spki(&bytes) {
            PublicKeyAlgorithm::PostQuantum {
                algorithm,
                key_bits,
            } => {
                assert_eq!(algorithm.name, "slh-dsa-sha2-128s");
                assert_eq!(key_bits, 256);
            }
            other => panic!("expected PostQuantum, got {:?}", other),
        }
    }

    #[test]
    fn composite_mldsa_parses_as_composite() {
        // id-MLDSA44-ECDSA-P256-SHA256 = 1.3.6.1.5.5.7.6.40
        let composite = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x28];
        let bytes = synthetic_spki(composite, 1312 + 65);
        match parse_spki(&bytes) {
            PublicKeyAlgorithm::PostQuantum { algorithm, .. } => {
                assert_eq!(algorithm.name, "mldsa44-ecdsa-p256-sha256");
                assert!(algorithm.composite);
            }
            other => panic!("expected PostQuantum, got {:?}", other),
        }
    }

    #[test]
    fn every_pq_table_entry_parses_to_its_name() {
        for entry in pq_algorithms::PQ_ALGORITHMS {
            let wire = pq_algorithms::encode_dotted_for_tests(entry.dotted);
            let bytes = synthetic_spki(&wire, 64);
            match parse_spki(&bytes) {
                PublicKeyAlgorithm::PostQuantum {
                    algorithm,
                    key_bits,
                } => {
                    assert_eq!(algorithm.name, entry.name);
                    assert_eq!(algorithm.composite, entry.composite);
                    assert_eq!(key_bits, 512);
                }
                other => panic!("expected PostQuantum for {}, got {:?}", entry.name, other),
            }
        }
    }

    #[test]
    fn ed25519_and_ed448_are_classified() {
        match parse_spki(&synthetic_spki(oid::OID_ED25519, 32)) {
            PublicKeyAlgorithm::EdDsa { name, key_bits } => {
                assert_eq!(name, "Ed25519");
                assert_eq!(key_bits, 256);
            }
            other => panic!("expected EdDsa, got {:?}", other),
        }
        match parse_spki(&synthetic_spki(oid::OID_ED448, 57)) {
            PublicKeyAlgorithm::EdDsa { name, key_bits } => {
                assert_eq!(name, "Ed448");
                assert_eq!(key_bits, 456);
            }
            other => panic!("expected EdDsa, got {:?}", other),
        }
    }

    #[test]
    fn wrong_length_eddsa_keys_collapse_to_unknown() {
        // RFC 8410 §3 fixes Ed25519 keys at 32 bytes and Ed448 keys at 57
        // bytes; anything else is not a valid key for that OID.
        match parse_spki(&synthetic_spki(oid::OID_ED25519, 31)) {
            PublicKeyAlgorithm::Unknown => {}
            other => panic!(
                "expected Unknown for a 31-byte Ed25519 key, got {:?}",
                other
            ),
        }
        match parse_spki(&synthetic_spki(oid::OID_ED448, 56)) {
            PublicKeyAlgorithm::Unknown => {}
            other => panic!("expected Unknown for a 56-byte Ed448 key, got {:?}", other),
        }
    }

    #[test]
    fn unrecognized_oid_still_collapses_to_unknown() {
        // 1.2.3.4, not RSA, not EC, not in the PQ table.
        let bytes = synthetic_spki(&[0x2a, 0x03, 0x04], 16);
        match parse_spki(&bytes) {
            PublicKeyAlgorithm::Unknown => {}
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn ec_curve_bit_length_p256() {
        // AlgorithmIdentifier { OID id-ecPublicKey, OID secp256r1 }
        let alg_oid = oid::OID_EC_PUBLIC_KEY;
        let curve_oid = oid::OID_SECP256R1;
        let mut alg_inner = Vec::new();
        alg_inner.push(tag::TAG_OBJECT_IDENTIFIER);
        alg_inner.push(alg_oid.len() as u8);
        alg_inner.extend(alg_oid);
        alg_inner.push(tag::TAG_OBJECT_IDENTIFIER);
        alg_inner.push(curve_oid.len() as u8);
        alg_inner.extend(curve_oid);
        let mut alg = vec![tag::TAG_SEQUENCE, alg_inner.len() as u8];
        alg.extend(&alg_inner);

        // Uncompressed P-256 point: 0x04 || 32 bytes X || 32 bytes Y = 65 bytes.
        let mut bs = vec![tag::TAG_BIT_STRING, 66];
        bs.push(0x00);
        bs.push(0x04);
        bs.extend(vec![0u8; 64]);

        let inner_len = alg.len() + bs.len();
        let mut spki = vec![tag::TAG_SEQUENCE, inner_len as u8];
        spki.extend(&alg);
        spki.extend(&bs);

        let mut r = DerReader::new(&spki);
        let spki = SubjectPublicKeyInfo::parse(&mut r).unwrap();
        match spki.parsed() {
            PublicKeyAlgorithm::Ec {
                curve_oid,
                key_bits,
            } => {
                assert_eq!(curve_oid.to_id_string(), "1.2.840.10045.3.1.7");
                assert_eq!(key_bits, 256);
            }
            other => panic!("expected EC, got {:?}", other),
        }
    }

    /// Build a minimal RSA SPKI around a raw modulus value, under
    /// `alg_oid` with `params` as the AlgorithmIdentifier parameters.
    fn rsa_spki_under(alg_oid: &[u8], params: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut key = der_tlv(tag::TAG_INTEGER, modulus);
        key.extend(der_tlv(tag::TAG_INTEGER, &[0x01, 0x00, 0x01]));
        let key = der_tlv(tag::TAG_SEQUENCE, &key);
        let mut alg = der_tlv(tag::TAG_OBJECT_IDENTIFIER, alg_oid);
        alg.extend_from_slice(params);
        let mut body = der_tlv(tag::TAG_SEQUENCE, &alg);
        let mut bits = vec![0u8];
        bits.extend(key);
        body.extend(der_tlv(tag::TAG_BIT_STRING, &bits));
        der_tlv(tag::TAG_SEQUENCE, &body)
    }

    /// Build a minimal rsaEncryption SPKI around a raw modulus value.
    fn rsa_spki(modulus: &[u8]) -> Vec<u8> {
        rsa_spki_under(oid::OID_RSA_ENCRYPTION, &[0x05, 0x00], modulus)
    }

    /// A 2048-bit modulus whose top bit is set, so DER prepends 0x00.
    fn modulus_2048() -> Vec<u8> {
        let mut modulus = vec![0x00u8, 0x80];
        modulus.extend(vec![0xffu8; 255]);
        modulus
    }

    fn rsa_bits(modulus: &[u8]) -> Option<usize> {
        let spki = rsa_spki(modulus);
        let mut r = DerReader::new(&spki);
        match SubjectPublicKeyInfo::parse(&mut r).unwrap().parsed() {
            PublicKeyAlgorithm::Rsa { modulus_bits, .. } => Some(modulus_bits),
            _ => None,
        }
    }

    #[test]
    fn rsassa_pss_keys_are_rsa_restricted_to_pss() {
        // RFC 4055 §1.2: id-RSASSA-PSS names an RSA public key, with
        // `RSASSA-PSS-params` optional. Both forms carry the same
        // RSAPublicKey in the BIT STRING, so the modulus is read the same
        // way; only the usage restriction (RFC 4055 §3.3) differs.
        let with_null = rsa_spki_under(oid::OID_RSASSA_PSS, &[0x05, 0x00], &modulus_2048());
        match parse_spki(&with_null) {
            PublicKeyAlgorithm::Rsa {
                modulus_bits,
                pss_only,
            } => {
                assert_eq!(modulus_bits, 2048);
                assert!(pss_only);
            }
            other => panic!("expected RSA, got {:?}", other),
        }

        // RSASSA-PSS-params naming SHA-256, MGF1-SHA-256, and a 32-byte
        // salt, the shape RFC 4055 §3.1 defines.
        let sha256 = der_tlv(tag::TAG_SEQUENCE, &{
            let mut inner = der_tlv(
                tag::TAG_OBJECT_IDENTIFIER,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            );
            inner.extend_from_slice(&[0x05, 0x00]);
            inner
        });
        let mgf1 = der_tlv(tag::TAG_SEQUENCE, &{
            let mut inner = der_tlv(
                tag::TAG_OBJECT_IDENTIFIER,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08],
            );
            inner.extend(sha256.clone());
            inner
        });
        let mut params_body = der_tlv(0xa0, &sha256);
        params_body.extend(der_tlv(0xa1, &mgf1));
        params_body.extend(der_tlv(0xa2, &der_tlv(tag::TAG_INTEGER, &[0x20])));
        let params = der_tlv(tag::TAG_SEQUENCE, &params_body);

        let with_params = rsa_spki_under(oid::OID_RSASSA_PSS, &params, &modulus_2048());
        match parse_spki(&with_params) {
            PublicKeyAlgorithm::Rsa {
                modulus_bits,
                pss_only,
            } => {
                assert_eq!(modulus_bits, 2048);
                assert!(pss_only);
            }
            other => panic!("expected RSA, got {:?}", other),
        }
    }

    #[test]
    fn rsa_encryption_keys_carry_no_pss_restriction() {
        match parse_spki(&rsa_spki(&modulus_2048())) {
            PublicKeyAlgorithm::Rsa {
                modulus_bits,
                pss_only,
            } => {
                assert_eq!(modulus_bits, 2048);
                assert!(!pss_only);
            }
            other => panic!("expected RSA, got {:?}", other),
        }
    }

    #[test]
    fn rsa_modulus_bits_count_leading_zero_bits() {
        // 256 bytes whose top byte is 0x01: a 2041-bit modulus, not 2048.
        let mut short = vec![0x01u8; 1];
        short.extend(vec![0xffu8; 255]);
        assert_eq!(rsa_bits(&short), Some(2041));
        // Top bit set: DER prepends 0x00, which must not count.
        let mut full = vec![0x00u8, 0x80];
        full.extend(vec![0xffu8; 255]);
        assert_eq!(rsa_bits(&full), Some(2048));
        // A modulus padded with a surplus zero byte is not valid DER.
        let mut padded = vec![0x00u8, 0x01];
        padded.extend(vec![0xffu8; 255]);
        assert_eq!(rsa_bits(&padded), None);
    }
}
