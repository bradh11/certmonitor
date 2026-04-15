// rust_certinfo/src/x509/spki.rs
//
// SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm        AlgorithmIdentifier,
//     subjectPublicKey BIT STRING
// }
//
// Two key types matter for the public web today: RSA and EC. For RSA we
// extract the modulus bit length from the inner SubjectPublicKey contents.
// For EC we extract the curve OID from `algorithm.parameters` (the
// **previous** code used `algorithm.oid()` here by mistake — that's
// id-ecPublicKey, not the curve — and this rewrite is the place we fix
// the bug). Other key types collapse to `Unknown`, matching the prior
// behavior so the Python-facing dict shape doesn't change.

use crate::der::{oid, tag, DerReader, Oid};
use crate::error::ParseError;
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
    Rsa { modulus_bits: usize },
    Ec { curve_oid: Oid<'a>, key_bits: usize },
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
            return parse_rsa(self.subject_public_key);
        }
        if alg_bytes == oid::OID_EC_PUBLIC_KEY {
            return parse_ec(self);
        }
        PublicKeyAlgorithm::Unknown
    }
}

/// RSA SubjectPublicKey: `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
/// We compute the modulus bit length the same way x509-parser does:
/// `modulus_bytes.len() * 8`, where `modulus_bytes` is the INTEGER value
/// **excluding** any leading 0x00 byte that DER inserts to keep the value
/// unsigned.
fn parse_rsa(subject_public_key: &[u8]) -> PublicKeyAlgorithm<'static> {
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
    // DER unsigned integers prepend 0x00 if the high bit is set; strip it
    // so we report the true bit length. x509-parser does the equivalent.
    let trimmed = if modulus.len() > 1 && modulus[0] == 0x00 {
        &modulus[1..]
    } else {
        modulus
    };
    PublicKeyAlgorithm::Rsa {
        modulus_bits: trimmed.len() * 8,
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

    /// Build a minimal SPKI for RSA-2048 with all-zero modulus (still
    /// 256 bytes long, which is what we measure).
    fn rsa_2048_spki() -> Vec<u8> {
        // RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
        // modulus: 257 bytes (0x00 || 256 zero bytes) so the trimmed
        // length is 256 bytes = 2048 bits.
        let mut modulus = vec![0x00u8];
        modulus.extend(vec![0u8; 256]);
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
            PublicKeyAlgorithm::Rsa { modulus_bits } => assert_eq!(modulus_bits, 2048),
            other => panic!("expected RSA, got {:?}", other),
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
}
