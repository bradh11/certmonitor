// rust_certinfo/src/crypto/rsa.rs
//
// RSASSA-PKCS1-v1_5 signature verification (RFC 8017 §8.2.2). The public
// key is the RSAPublicKey inside a SubjectPublicKeyInfo; the digest is
// computed by the caller. Verification recovers the encoded message
// s^e mod n and compares it, byte for byte, with the expected
// `00 01 FF..FF 00 || DigestInfo` encoding.

use crate::crypto::bigint::BigUint;
use crate::crypto::VerifyError;
use crate::der::{tag, DerReader};

/// The hash algorithms PKCS#1 v1.5 signatures may name in DigestInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// The `hashlib` name Python uses to produce the digest.
    #[cfg_attr(not(feature = "python"), allow(dead_code))]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// DER of `AlgorithmIdentifier { oid, NULL }` for DigestInfo.
    fn algorithm_der(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[
                0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
            ],
            Self::Sha256 => &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00,
            ],
            Self::Sha384 => &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                0x00,
            ],
            Self::Sha512 => &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00,
            ],
        }
    }
}

/// OpenSSL's `OPENSSL_RSA_MAX_MODULUS_BITS`: no CA issues anything larger,
/// and modular exponentiation cost grows with the cube of the modulus size.
const MAX_MODULUS_BITS: usize = 16384;
/// OpenSSL's `OPENSSL_RSA_MAX_PUBEXP_BITS`: real public exponents are 3 or
/// 65537; a huge exponent only serves to make verification slow.
const MAX_EXPONENT_BITS: usize = 64;

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(Debug)]
pub struct RsaPublicKey {
    pub modulus: BigUint,
    pub exponent: BigUint,
}

impl RsaPublicKey {
    /// Parse the BIT STRING contents of an rsaEncryption SubjectPublicKeyInfo.
    pub fn from_der(bytes: &[u8]) -> Result<Self, VerifyError> {
        let mut top = DerReader::new(bytes);
        let mut seq = top
            .expect_constructed(tag::TAG_SEQUENCE)
            .map_err(|_| VerifyError::Malformed("RSAPublicKey"))?;
        let modulus = seq
            .expect(tag::TAG_INTEGER)
            .map_err(|_| VerifyError::Malformed("RSA modulus"))?;
        let exponent = seq
            .expect(tag::TAG_INTEGER)
            .map_err(|_| VerifyError::Malformed("RSA exponent"))?;
        seq.end()
            .map_err(|_| VerifyError::Malformed("RSAPublicKey"))?;
        let modulus = BigUint::from_der_positive(modulus)
            .ok_or(VerifyError::Malformed("RSA modulus encoding"))?;
        let exponent = BigUint::from_der_positive(exponent)
            .ok_or(VerifyError::Malformed("RSA exponent encoding"))?;
        if modulus.bit_len() < 512 || !modulus.is_odd() || exponent < BigUint::from_u64(3) {
            return Err(VerifyError::Malformed("RSA key parameters"));
        }
        if modulus.bit_len() > MAX_MODULUS_BITS {
            return Err(VerifyError::Unsupported(format!(
                "RSA modulus of {} bits (limit {MAX_MODULUS_BITS})",
                modulus.bit_len()
            )));
        }
        if exponent.bit_len() > MAX_EXPONENT_BITS {
            return Err(VerifyError::Unsupported(format!(
                "RSA public exponent of {} bits (limit {MAX_EXPONENT_BITS})",
                exponent.bit_len()
            )));
        }
        Ok(Self { modulus, exponent })
    }

    /// The modulus length in bytes, which is also the signature length.
    pub fn size(&self) -> usize {
        self.modulus.bit_len().div_ceil(8)
    }
}

/// Verify `signature` over `digest` (already hashed with `hash`).
pub fn verify(
    key: &RsaPublicKey,
    hash: HashAlg,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    if digest.len() != hash.digest_len() {
        return Err(VerifyError::Malformed("digest length"));
    }
    let k = key.size();
    if signature.len() != k {
        return Ok(false);
    }
    let s = BigUint::from_be_bytes(signature);
    if s >= key.modulus {
        return Ok(false);
    }
    let Some(encoded) = s.mod_pow(&key.exponent, &key.modulus).to_be_bytes(k) else {
        return Ok(false);
    };

    // EMSA-PKCS1-v1_5: 00 01 PS 00 T, with PS at least eight 0xff bytes.
    let mut t = Vec::with_capacity(hash.algorithm_der().len() + digest.len() + 4);
    let inner_len = hash.algorithm_der().len() + 2 + digest.len();
    t.push(tag::TAG_SEQUENCE);
    t.push(inner_len as u8);
    t.extend_from_slice(hash.algorithm_der());
    t.push(tag::TAG_OCTET_STRING);
    t.push(digest.len() as u8);
    t.extend_from_slice(digest);
    if k < t.len() + 11 {
        return Ok(false);
    }
    let mut expected = vec![0x00, 0x01];
    expected.resize(k - t.len() - 1, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(&t);
    Ok(expected == encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_vectors::{hex, DIGEST256, RSA_SIG, RSA_SPKI};
    use crate::x509::spki::SubjectPublicKeyInfo;

    fn key() -> RsaPublicKey {
        let spki_der = hex(RSA_SPKI);
        let mut reader = DerReader::new(&spki_der);
        let spki = SubjectPublicKeyInfo::parse(&mut reader).unwrap();
        RsaPublicKey::from_der(spki.subject_public_key).unwrap()
    }

    #[test]
    fn openssl_signature_verifies() {
        let key = key();
        assert_eq!(key.size(), 256);
        assert_eq!(key.exponent, BigUint::from_u64(65537));
        assert!(verify(&key, HashAlg::Sha256, &hex(DIGEST256), &hex(RSA_SIG)).unwrap());
    }

    #[test]
    fn tampering_is_detected() {
        let key = key();
        let mut digest = hex(DIGEST256);
        digest[0] ^= 1;
        assert!(!verify(&key, HashAlg::Sha256, &digest, &hex(RSA_SIG)).unwrap());
        let mut signature = hex(RSA_SIG);
        signature[10] ^= 1;
        assert!(!verify(&key, HashAlg::Sha256, &hex(DIGEST256), &signature).unwrap());
        assert!(!verify(&key, HashAlg::Sha256, &hex(DIGEST256), &signature[1..]).unwrap());
        // A "signature" at least as large as the modulus is rejected outright.
        let too_big = vec![0xff; 256];
        assert!(!verify(&key, HashAlg::Sha256, &hex(DIGEST256), &too_big).unwrap());
        // The wrong hash algorithm changes DigestInfo and fails to match.
        let digest48 = vec![0u8; 48];
        assert!(!verify(&key, HashAlg::Sha384, &digest48, &hex(RSA_SIG)).unwrap());
        assert_eq!(
            verify(&key, HashAlg::Sha256, &digest48, &hex(RSA_SIG)).unwrap_err(),
            VerifyError::Malformed("digest length")
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert!(RsaPublicKey::from_der(&[0x30, 0x00]).is_err());
        assert!(RsaPublicKey::from_der(&[0x04, 0x01, 0x00]).is_err());
        // A tiny modulus is not a usable RSA key.
        assert!(RsaPublicKey::from_der(&[0x30, 0x06, 0x02, 0x01, 0x0d, 0x02, 0x01, 0x03]).is_err());
    }

    fn rsa_key_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 128 {
                out.push(content.len() as u8);
            } else {
                let len_bytes: Vec<u8> = content
                    .len()
                    .to_be_bytes()
                    .iter()
                    .copied()
                    .skip_while(|b| *b == 0)
                    .collect();
                out.push(0x80 | len_bytes.len() as u8);
                out.extend_from_slice(&len_bytes);
            }
            out.extend_from_slice(content);
            out
        }
        let mut body = tlv(tag::TAG_INTEGER, modulus);
        body.extend(tlv(tag::TAG_INTEGER, exponent));
        tlv(tag::TAG_SEQUENCE, &body)
    }

    #[test]
    fn oversized_parameters_are_unsupported_not_computed() {
        let mut modulus = vec![0x00u8, 0xff];
        modulus.extend(vec![0xffu8; 255]); // 2048 bits, odd
        let mut huge_e = vec![0x01u8];
        huge_e.extend(vec![0x00u8; 8]); // 2^64: 65 bits
        huge_e[8] = 0x01;
        let err = RsaPublicKey::from_der(&rsa_key_der(&modulus, &huge_e)).unwrap_err();
        assert!(matches!(err, VerifyError::Unsupported(_)), "{err:?}");
        let mut giant_n = vec![0x00u8, 0xff];
        giant_n.extend(vec![0xffu8; 2048]); // 16392 bits
        let err = RsaPublicKey::from_der(&rsa_key_der(&giant_n, &[0x01, 0x00, 0x01])).unwrap_err();
        assert!(matches!(err, VerifyError::Unsupported(_)), "{err:?}");
        // 64-bit exponents and 16384-bit moduli stay within bounds.
        let mut max_e = vec![0x00u8, 0xff];
        max_e.extend(vec![0xffu8; 7]);
        assert!(RsaPublicKey::from_der(&rsa_key_der(&modulus, &max_e)).is_ok());
    }
}
