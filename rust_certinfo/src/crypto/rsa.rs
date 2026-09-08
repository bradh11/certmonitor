// rust_certinfo/src/crypto/rsa.rs
//
// The RSA half of signature verification. The public key is the
// RSAPublicKey inside a SubjectPublicKeyInfo and the digest is computed by
// the caller. Four things live here:
//
//   - RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2), start to finish:
//     recover the encoded message and compare it, byte for byte, with the
//     expected `00 01 FF..FF 00 || DigestInfo` encoding.
//   - RSAVP1 (§5.2.2), the `s^e mod n` primitive both schemes stand on.
//   - The RSASSA-PSS encoded message: RSAVP1 plus the §8.1.2 step 2.c trim
//     to `emLen` octets, with the modulus bit length the caller needs. The
//     PSS padding check itself is in Python, in `certmonitor.signatures`,
//     because that is where the hashing is.
//   - RSASSA-PSS-params parsing (RFC 4055 §3.1): the two hash algorithms,
//     the MGF1 mask generation function, the salt length, and the trailer
//     field, each with the RFC's default when absent.

use crate::crypto::bigint::BigUint;
use crate::crypto::VerifyError;
use crate::der::{tag, DerReader};
use crate::x509::algorithm::AlgorithmIdentifier;

/// A hash algorithm named by a signature scheme: in a PKCS#1 v1.5
/// DigestInfo, or as either the message hash or the MGF1 hash of
/// RSASSA-PSS-params. These four are what RFC 4055 §2.1 defines.
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

/// `s^e mod n` as a `k`-byte string (RFC 8017 §5.2.2 RSAVP1 followed by
/// I2OSP), for schemes whose padding is checked by the caller (RSASSA-PSS
/// in Python; PKCS#1 v1.5 `verify` below checks its own padding).
pub fn public_operation(key: &RsaPublicKey, signature: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let k = key.size();
    if signature.len() != k {
        return Err(VerifyError::Malformed("RSA signature length"));
    }
    let s = BigUint::from_be_bytes(signature);
    if s >= key.modulus {
        return Err(VerifyError::Malformed("RSA signature out of range"));
    }
    s.mod_pow(&key.exponent, &key.modulus)
        .to_be_bytes(k)
        .ok_or(VerifyError::Malformed("RSA public operation width"))
}

/// The RSASSA-PSS encoded message and the modulus's exact bit length.
///
/// RFC 8017 §8.1.2 step 2.c encodes `EM` as `I2OSP(m, emLen)` with
/// `emLen = ceil(emBits / 8)` and `emBits = modBits - 1`, which is one octet
/// shorter than the `k`-byte RSAVP1 result whenever `modBits` is 1 mod 8.
/// Returning `emLen` octets here, together with `modBits`, keeps the caller
/// from having to rediscover the modulus's bit length to find where `EM`
/// starts. The octets dropped from the front must all be zero, or `m` does
/// not fit in `emBits` bits.
pub fn pss_encoded_message(
    key: &RsaPublicKey,
    signature: &[u8],
) -> Result<(Vec<u8>, usize), VerifyError> {
    let em = public_operation(key, signature)?;
    let mod_bits = key.modulus.bit_len();
    let em_len = (mod_bits - 1).div_ceil(8);
    let leading = em.len() - em_len;
    if em[..leading].iter().any(|b| *b != 0) {
        return Err(VerifyError::Malformed("PSS encoded message exceeds emBits"));
    }
    Ok((em[leading..].to_vec(), mod_bits))
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
    let encoded = match public_operation(key, signature) {
        Ok(bytes) => bytes,
        Err(VerifyError::Malformed(_)) => return Ok(false),
        Err(err) => return Err(err),
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

/// RSASSA-PSS-params (RFC 4055 §3.1) with the defaults the RFC specifies:
///
/// ```text
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm     [0] HashAlgorithm    DEFAULT sha1Identifier,
///     maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
///     saltLength        [2] INTEGER          DEFAULT 20,
///     trailerField      [3] TrailerField     DEFAULT trailerFieldBC
/// }
/// ```
///
/// Only MGF1 (RFC 4055 §A.2.3) is supported as `maskGenAlgorithm`, and only
/// SHA-1, SHA-256, SHA-384, and SHA-512 (§2.1) as either hash. `salt_length`
/// and `trailer_field` are the plain integer values; a `trailerField` other
/// than 1 (`trailerFieldBC`, the only value RFC 4055 defines) is
/// unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParameters {
    pub hash: HashAlg,
    pub mgf_hash: HashAlg,
    pub salt_length: usize,
    pub trailer_field: u8,
}

/// id-mgf1 (1.2.840.113549.1.1.8), the only maskGenAlgorithm RFC 4055
/// defines for RSASSA-PSS.
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

/// Map a HashAlgorithm's OID (RFC 4055 §2.1) to a [`HashAlg`].
fn hash_alg_from_oid(oid: crate::der::Oid<'_>) -> Result<HashAlg, VerifyError> {
    match oid.to_id_string().as_str() {
        "1.3.14.3.2.26" => Ok(HashAlg::Sha1),
        "2.16.840.1.101.3.4.2.1" => Ok(HashAlg::Sha256),
        "2.16.840.1.101.3.4.2.2" => Ok(HashAlg::Sha384),
        "2.16.840.1.101.3.4.2.3" => Ok(HashAlg::Sha512),
        other => Err(VerifyError::Unsupported(format!(
            "PSS hash algorithm {other}"
        ))),
    }
}

/// Decode a DER INTEGER's value bytes as a small unsigned integer. RSASSA-
/// PSS `saltLength` and `trailerField` are always tiny in practice, so a
/// value that does not fit in a `u64`, or is negative, is rejected outright
/// rather than silently truncated.
fn small_uint(value: &[u8]) -> Result<u64, VerifyError> {
    const ERR: VerifyError = VerifyError::Malformed("PSS parameter integer");
    if value.is_empty() {
        return Err(ERR);
    }
    // A leading 0x00 is a sign byte (present only so the next byte's high
    // bit isn't mistaken for a sign) unless it is the whole value, i.e. 0.
    let (had_sign_byte, digits) = match value {
        [0x00, rest @ ..] if !rest.is_empty() => (true, rest),
        _ => (false, value),
    };
    if digits.len() > 8 {
        return Err(ERR);
    }
    if !had_sign_byte && digits[0] & 0x80 != 0 {
        return Err(ERR);
    }
    if had_sign_byte && digits[0] == 0x00 {
        // Two leading zero octets: DER (X.690 §8.3.2) allows the sign byte
        // only when the next octet's high bit is set, so this is a padded
        // re-encoding of a smaller value, not a value in its own right.
        return Err(ERR);
    }
    digits
        .iter()
        .try_fold(0u64, |acc, &b| {
            acc.checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(b)))
        })
        .ok_or(ERR)
}

impl PssParameters {
    /// RFC 4055 §3.1 defaults: SHA-1 for both hashes, a 20-byte salt, and
    /// the only defined trailer field value.
    fn defaults() -> Self {
        Self {
            hash: HashAlg::Sha1,
            mgf_hash: HashAlg::Sha1,
            salt_length: 20,
            trailer_field: 1,
        }
    }

    /// Parse `RSASSA-PSS-params`, or the RFC 4055 defaults when `params`
    /// is `None` (an AlgorithmIdentifier with absent or NULL parameters).
    pub fn parse(params: Option<&[u8]>) -> Result<Self, VerifyError> {
        let Some(raw) = params else {
            return Ok(Self::defaults());
        };
        let mut top = DerReader::new(raw);
        let mut seq = top
            .expect_constructed(tag::TAG_SEQUENCE)
            .map_err(|_| VerifyError::Malformed("RSASSA-PSS-params"))?;
        top.end()
            .map_err(|_| VerifyError::Malformed("RSASSA-PSS-params"))?;

        let mut result = Self::defaults();

        if let Some(0xa0) = seq.peek_tag() {
            let mut wrapper = seq
                .expect_constructed(0xa0)
                .map_err(|_| VerifyError::Malformed("PSS hashAlgorithm"))?;
            let alg = AlgorithmIdentifier::parse(&mut wrapper)
                .map_err(|_| VerifyError::Malformed("PSS hashAlgorithm"))?;
            wrapper
                .end()
                .map_err(|_| VerifyError::Malformed("PSS hashAlgorithm"))?;
            result.hash = hash_alg_from_oid(alg.algorithm)?;
        }

        if let Some(0xa1) = seq.peek_tag() {
            let mut wrapper = seq
                .expect_constructed(0xa1)
                .map_err(|_| VerifyError::Malformed("PSS maskGenAlgorithm"))?;
            let mgf = AlgorithmIdentifier::parse(&mut wrapper)
                .map_err(|_| VerifyError::Malformed("PSS maskGenAlgorithm"))?;
            wrapper
                .end()
                .map_err(|_| VerifyError::Malformed("PSS maskGenAlgorithm"))?;
            if mgf.algorithm.as_bytes() != OID_MGF1 {
                return Err(VerifyError::Unsupported(format!(
                    "PSS mask generation function {}",
                    mgf.algorithm.to_id_string()
                )));
            }
            // RFC 4055 §2.1 always carries the hash AlgorithmIdentifier inside
            // MGF1's parameters, so an absent one is a malformed encoding, not
            // a default to fall back on.
            let mgf_params = mgf
                .parameters
                .ok_or(VerifyError::Malformed("PSS maskGenAlgorithm parameters"))?;
            let mut mgf_reader = DerReader::new(mgf_params);
            let mgf_hash_alg = AlgorithmIdentifier::parse(&mut mgf_reader)
                .map_err(|_| VerifyError::Malformed("PSS MGF1 hashAlgorithm"))?;
            mgf_reader
                .end()
                .map_err(|_| VerifyError::Malformed("PSS MGF1 hashAlgorithm"))?;
            result.mgf_hash = hash_alg_from_oid(mgf_hash_alg.algorithm)?;
        }

        if let Some(0xa2) = seq.peek_tag() {
            let mut wrapper = seq
                .expect_constructed(0xa2)
                .map_err(|_| VerifyError::Malformed("PSS saltLength"))?;
            let value = wrapper
                .expect(tag::TAG_INTEGER)
                .map_err(|_| VerifyError::Malformed("PSS saltLength"))?;
            wrapper
                .end()
                .map_err(|_| VerifyError::Malformed("PSS saltLength"))?;
            result.salt_length = small_uint(value)?
                .try_into()
                .map_err(|_| VerifyError::Malformed("PSS saltLength"))?;
        }

        if let Some(0xa3) = seq.peek_tag() {
            let mut wrapper = seq
                .expect_constructed(0xa3)
                .map_err(|_| VerifyError::Malformed("PSS trailerField"))?;
            let value = wrapper
                .expect(tag::TAG_INTEGER)
                .map_err(|_| VerifyError::Malformed("PSS trailerField"))?;
            wrapper
                .end()
                .map_err(|_| VerifyError::Malformed("PSS trailerField"))?;
            let trailer_field = small_uint(value)?;
            if trailer_field != 1 {
                return Err(VerifyError::Unsupported(format!(
                    "PSS trailer field {trailer_field}"
                )));
            }
            result.trailer_field = 1;
        }

        seq.end()
            .map_err(|_| VerifyError::Malformed("RSASSA-PSS-params"))?;
        Ok(result)
    }
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
    fn public_operation_recovers_the_encoded_message() {
        let key = key();
        let em = public_operation(&key, &hex(RSA_SIG)).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(&em[..2], &[0x00, 0x01]); // PKCS#1 v1.5 block type
        assert!(public_operation(&key, &hex(RSA_SIG)[1..]).is_err());
        let too_big = vec![0xff; 256];
        assert!(public_operation(&key, &too_big).is_err());
    }

    #[test]
    fn pss_encoded_message_is_em_len_octets_long() {
        // 2048 bits is 0 mod 8, so emLen == k and EM is the whole result.
        let key = key();
        let (em, mod_bits) = pss_encoded_message(&key, &hex(RSA_SIG)).unwrap();
        assert_eq!(mod_bits, 2048);
        assert_eq!(em.len(), 256);
        assert_eq!(em, public_operation(&key, &hex(RSA_SIG)).unwrap());
    }

    #[test]
    fn pss_encoded_message_rejects_a_value_wider_than_em_bits() {
        // n = 2^2049 - 1, so modBits is 2049, k is 257, and emLen is 256:
        // the leading octet of the k-byte result has to be zero.
        let mut modulus = vec![0x01u8];
        modulus.extend(vec![0xffu8; 256]);
        let key = RsaPublicKey::from_der(&rsa_key_der(&modulus, &[0x03])).unwrap();
        assert_eq!(key.modulus.bit_len(), 2049);
        assert_eq!(key.size(), 257);
        // s = 2^683 - 1, whose cube is below n and at or above 2^2048.
        let mut signature = vec![0x00u8; 171];
        signature.push(0x07);
        signature.extend(vec![0xffu8; 85]);
        assert_ne!(public_operation(&key, &signature).unwrap()[0], 0);
        assert_eq!(
            pss_encoded_message(&key, &signature).unwrap_err(),
            VerifyError::Malformed("PSS encoded message exceeds emBits")
        );
    }

    #[test]
    fn pss_parameters_defaults_and_explicit_values() {
        let defaults = PssParameters::parse(None).unwrap();
        assert_eq!(defaults.hash, HashAlg::Sha1);
        assert_eq!(defaults.mgf_hash, HashAlg::Sha1);
        assert_eq!(defaults.salt_length, 20);
        // An explicit, empty SEQUENCE also carries only the RFC 4055 defaults.
        let empty = PssParameters::parse(Some(&hex("3000"))).unwrap();
        assert_eq!(empty, defaults);
        // SEQUENCE { [0] sha256, [1] mgf1(sha256), [2] 32 }
        let params = hex(
            "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
        );
        let parsed = PssParameters::parse(Some(&params)).unwrap();
        assert_eq!(parsed.hash, HashAlg::Sha256);
        assert_eq!(parsed.mgf_hash, HashAlg::Sha256);
        assert_eq!(parsed.salt_length, 32);
        assert_eq!(parsed.trailer_field, 1);
    }

    #[test]
    fn small_uint_rejects_overflow_and_negative_values() {
        // [3] INTEGER 01 00 00 00 00 00 00 00 01 (2^64 + 1): too wide for a u64.
        let value = hex("010000000000000001");
        assert_eq!(
            small_uint(&value).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
        // [2] INTEGER ff: the high bit with no 0x00 sign byte means -1.
        let value = hex("ff");
        assert_eq!(
            small_uint(&value).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
        // [2] INTEGER 00 20: a sign byte ahead of a positive value.
        assert_eq!(small_uint(&hex("0020")).unwrap(), 32);
        // An empty value has no digits to fold.
        assert_eq!(
            small_uint(&[]).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
        // The minimal DER encoding of zero.
        assert_eq!(small_uint(&hex("00")).unwrap(), 0);
    }

    #[test]
    fn small_uint_requires_minimal_der() {
        // [2] INTEGER 00 00 20: a second leading zero octet, which X.690
        // §8.3.2 forbids because the first one alone already encodes 32.
        assert_eq!(
            small_uint(&hex("000020")).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
        // [2] INTEGER 00 80: the sign byte the same rule requires, since
        // 0x80's high bit would otherwise read as negative.
        assert_eq!(small_uint(&hex("0080")).unwrap(), 128);
    }

    #[test]
    fn pss_parameters_reject_integer_overflow() {
        // saltLength [2] INTEGER 01 00 00 00 00 00 00 00 01 (2^64 + 1).
        let params = hex("300da20b0209010000000000000001");
        assert_eq!(
            PssParameters::parse(Some(&params)).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
        // trailerField [3] INTEGER ff: the high bit with no sign byte is -1,
        // not a valid trailerField.
        let params = hex("3005a3030201ff");
        assert_eq!(
            PssParameters::parse(Some(&params)).unwrap_err(),
            VerifyError::Malformed("PSS parameter integer")
        );
    }

    #[test]
    fn pss_parameters_unsupported_paths() {
        // maskGenAlgorithm naming something other than MGF1.
        let params = hex("3011a10f300d06092a864886f70d0101070500");
        let err = PssParameters::parse(Some(&params)).unwrap_err();
        assert!(matches!(err, VerifyError::Unsupported(_)), "{err:?}");
        // hashAlgorithm sha3-256, which RFC 4055 does not name for PSS.
        let params = hex("3011a00f300d06096086480165030402080500");
        let err = PssParameters::parse(Some(&params)).unwrap_err();
        assert!(matches!(err, VerifyError::Unsupported(_)), "{err:?}");
        // trailerField 2: RFC 4055 defines only trailerFieldBC (1).
        let params = hex("3005a303020102");
        let err = PssParameters::parse(Some(&params)).unwrap_err();
        assert!(matches!(err, VerifyError::Unsupported(_)), "{err:?}");
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
