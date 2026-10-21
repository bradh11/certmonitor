// rust_certinfo/src/x509/weak_key.rs
//
// Public keys whose private half anyone can recover from the key alone.
// This is detection, not a general entropy test: a key only fails here
// when it has a recognizable structure, and passing proves nothing about
// how well the key was generated.

use crate::crypto::bigint::BigUint;
use crate::crypto::{ecdsa, VerifyError};
use crate::der::DerReader;
use crate::x509::spki::{PublicKeyAlgorithm, SubjectPublicKeyInfo};
use crate::x509::verify::curve_for;

/// The largest search `ec_small_scalar` accepts. Past the precomputed
/// table, each candidate costs one point addition (about 8 microseconds on
/// P-384 in a release build), so this ceiling is a couple of minutes per
/// key, not days.
pub const MAX_SMALL_SCALAR_BOUND: u64 = 1 << 24;

/// The private scalar of the EC key in `spki_der` when it, or its negation
/// mod n, is at most `bound` (see `ecdsa::small_scalar`). `Ok(None)` means
/// no such scalar; `Err` means the key is not a P-256, P-384, or P-521 key,
/// does not parse, or `bound` is above `MAX_SMALL_SCALAR_BOUND`.
pub fn ec_small_scalar(spki_der: &[u8], bound: u64) -> Result<Option<BigUint>, VerifyError> {
    if bound > MAX_SMALL_SCALAR_BOUND {
        return Err(VerifyError::Unsupported(format!(
            "small-scalar bound above {MAX_SMALL_SCALAR_BOUND}"
        )));
    }
    let mut reader = DerReader::new(spki_der);
    let spki = SubjectPublicKeyInfo::parse(&mut reader)
        .map_err(|_| VerifyError::Malformed("SubjectPublicKeyInfo"))?;
    let PublicKeyAlgorithm::Ec { curve_oid, .. } = spki.parsed() else {
        return Err(VerifyError::Unsupported("key type (not an EC key)".into()));
    };
    let key = ecdsa::PublicKey::from_sec1(curve_for(curve_oid)?, spki.subject_public_key)?;
    Ok(ecdsa::small_scalar(&key, bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_vectors::{
        hex, EMUDHRA_OV_TLS_G3C_SPKI, P256_SPKI, P384_SPKI, RSA_SPKI,
    };

    #[test]
    fn recovers_the_scalar_of_a_weak_ec_key() {
        assert_eq!(
            ec_small_scalar(&hex(EMUDHRA_OV_TLS_G3C_SPKI), 256),
            Ok(Some(BigUint::from_u64(4)))
        );
    }

    #[test]
    fn properly_generated_ec_keys_report_none() {
        assert_eq!(ec_small_scalar(&hex(P256_SPKI), 256), Ok(None));
        assert_eq!(ec_small_scalar(&hex(P384_SPKI), 256), Ok(None));
    }

    #[test]
    fn non_ec_and_malformed_keys_are_errors() {
        assert!(matches!(
            ec_small_scalar(&hex(RSA_SPKI), 256),
            Err(VerifyError::Unsupported(_))
        ));
        assert_eq!(
            ec_small_scalar(&[0x30, 0x00], 256),
            Err(VerifyError::Malformed("SubjectPublicKeyInfo"))
        );
    }

    #[test]
    fn a_bound_above_the_ceiling_is_refused_before_any_arithmetic() {
        assert_eq!(
            ec_small_scalar(&hex(P256_SPKI), MAX_SMALL_SCALAR_BOUND + 1),
            Err(VerifyError::Unsupported(format!(
                "small-scalar bound above {MAX_SMALL_SCALAR_BOUND}"
            )))
        );
    }
}
