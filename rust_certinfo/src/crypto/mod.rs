// rust_certinfo/src/crypto/mod.rs
//
// Signature verification for OCSP responses and CRLs, standard library
// only. This is verification, not signing: there is no private key here,
// so there are no secrets to protect and no side channels to close. A bug
// yields a wrong verdict, which the tests against published vectors and
// real OpenSSL output are there to catch.
//
//   bigint.rs, unsigned big integers (multiply, divide, modular power)
//   rsa.rs   , RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2)
//   ecdsa.rs , ECDSA verification over P-256 and P-384 (FIPS 186-4)

pub mod bigint;
pub mod ecdsa;
pub mod rsa;
#[cfg(test)]
pub mod test_vectors;

/// Why a signature could not be checked (as opposed to checking and
/// finding it invalid, which is a plain `false`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature or public key algorithm is not one we implement.
    Unsupported(String),
    /// The key, signature, or digest bytes are structurally wrong.
    Malformed(&'static str),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Unsupported(what) => write!(f, "unsupported {what}"),
            VerifyError::Malformed(what) => write!(f, "malformed {what}"),
        }
    }
}

impl std::error::Error for VerifyError {}
