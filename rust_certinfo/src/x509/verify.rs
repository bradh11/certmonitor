// rust_certinfo/src/x509/verify.rs
//
// Signature verification for X.509 structures: which hash a signature
// algorithm implies, which key it needs, and the one `verify_signature`
// call that checks a digest against a SubjectPublicKeyInfo. Used for OCSP
// responses, delegated responder certificates, and CRLs.

use crate::crypto::{ecdsa, rsa, VerifyError};
use crate::der::{oid, DerReader, Oid};
use crate::x509::spki::{PublicKeyAlgorithm, SubjectPublicKeyInfo};

pub use crate::crypto::rsa::HashAlg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Rsa,
    Ecdsa,
}

/// The hash and key type a signature algorithm OID (dotted form) names.
pub fn signature_algorithm(dotted: &str) -> Option<(SignatureKind, HashAlg)> {
    Some(match dotted {
        "1.2.840.113549.1.1.5" => (SignatureKind::Rsa, HashAlg::Sha1),
        "1.2.840.113549.1.1.11" => (SignatureKind::Rsa, HashAlg::Sha256),
        "1.2.840.113549.1.1.12" => (SignatureKind::Rsa, HashAlg::Sha384),
        "1.2.840.113549.1.1.13" => (SignatureKind::Rsa, HashAlg::Sha512),
        "1.2.840.10045.4.1" => (SignatureKind::Ecdsa, HashAlg::Sha1),
        "1.2.840.10045.4.3.2" => (SignatureKind::Ecdsa, HashAlg::Sha256),
        "1.2.840.10045.4.3.3" => (SignatureKind::Ecdsa, HashAlg::Sha384),
        "1.2.840.10045.4.3.4" => (SignatureKind::Ecdsa, HashAlg::Sha512),
        _ => return None,
    })
}

/// Check `signature` over `digest` (already hashed as `algorithm` implies)
/// with the key in `spki_der`. `Ok(false)` is a signature that does not
/// verify; `Err` means the check could not be performed at all.
pub fn verify_signature(
    algorithm: &str,
    digest: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<bool, VerifyError> {
    let (kind, hash) = signature_algorithm(algorithm)
        .ok_or_else(|| VerifyError::Unsupported(format!("signature algorithm {algorithm}")))?;
    if digest.len() != hash.digest_len() {
        return Err(VerifyError::Malformed("digest length"));
    }
    let mut reader = DerReader::new(spki_der);
    let spki = SubjectPublicKeyInfo::parse(&mut reader)
        .map_err(|_| VerifyError::Malformed("SubjectPublicKeyInfo"))?;
    match (kind, spki.parsed()) {
        (SignatureKind::Rsa, PublicKeyAlgorithm::Rsa { .. }) => {
            let key = rsa::RsaPublicKey::from_der(spki.subject_public_key)?;
            rsa::verify(&key, hash, digest, signature)
        }
        (SignatureKind::Ecdsa, PublicKeyAlgorithm::Ec { curve_oid, .. }) => {
            let curve = curve_for(curve_oid)?;
            let key = ecdsa::PublicKey::from_sec1(curve, spki.subject_public_key)?;
            ecdsa::verify(&key, digest, signature)
        }
        (_, PublicKeyAlgorithm::PostQuantum { algorithm, .. }) => Err(VerifyError::Unsupported(
            format!("post-quantum signature verification ({})", algorithm.name),
        )),
        _ => Err(VerifyError::Unsupported(
            "signature algorithm does not match the key type".into(),
        )),
    }
}

fn curve_for(curve_oid: Oid<'_>) -> Result<ecdsa::Curve, VerifyError> {
    match curve_oid.as_bytes() {
        bytes if bytes == oid::OID_SECP256R1 => Ok(ecdsa::Curve::P256),
        bytes if bytes == oid::OID_SECP384R1 => Ok(ecdsa::Curve::P384),
        _ => Err(VerifyError::Unsupported(format!(
            "EC curve {} (only P-256 and P-384 are supported)",
            curve_oid.to_id_string()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_vectors::{
        hex, DIGEST256, DIGEST384, P256_SIG, P256_SPKI, P384_SIG, P384_SPKI, RSA_SIG, RSA_SPKI,
    };

    #[test]
    fn dispatches_on_algorithm_and_key_type() {
        let sha256_rsa = "1.2.840.113549.1.1.11";
        assert!(
            verify_signature(sha256_rsa, &hex(DIGEST256), &hex(RSA_SIG), &hex(RSA_SPKI)).unwrap()
        );
        assert!(verify_signature(
            "1.2.840.10045.4.3.2",
            &hex(DIGEST256),
            &hex(P256_SIG),
            &hex(P256_SPKI)
        )
        .unwrap());
        assert!(verify_signature(
            "1.2.840.10045.4.3.3",
            &hex(DIGEST384),
            &hex(P384_SIG),
            &hex(P384_SPKI)
        )
        .unwrap());
        // Wrong key for the algorithm, unknown algorithm, wrong digest size.
        assert!(matches!(
            verify_signature(sha256_rsa, &hex(DIGEST256), &hex(RSA_SIG), &hex(P256_SPKI)),
            Err(VerifyError::Unsupported(_))
        ));
        assert!(matches!(
            verify_signature(
                "1.2.840.113549.1.1.10",
                &hex(DIGEST256),
                &hex(RSA_SIG),
                &hex(RSA_SPKI)
            ),
            Err(VerifyError::Unsupported(_))
        ));
        assert_eq!(
            verify_signature(sha256_rsa, &hex(DIGEST384), &hex(RSA_SIG), &hex(RSA_SPKI))
                .unwrap_err(),
            VerifyError::Malformed("digest length")
        );
        assert!(
            verify_signature(sha256_rsa, &hex(DIGEST256), &hex(RSA_SIG), &[0x30, 0x00]).is_err()
        );
    }

    #[test]
    fn algorithm_table() {
        assert_eq!(
            signature_algorithm("1.2.840.113549.1.1.5"),
            Some((SignatureKind::Rsa, HashAlg::Sha1))
        );
        assert_eq!(
            signature_algorithm("1.2.840.10045.4.3.4"),
            Some((SignatureKind::Ecdsa, HashAlg::Sha512))
        );
        assert_eq!(signature_algorithm("1.3.101.112"), None);
        assert_eq!(HashAlg::Sha512.name(), "sha512");
    }
}
