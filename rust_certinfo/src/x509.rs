// rust_certinfo/src/x509.rs
//
// X.509 layer. Composes the DER primitives in `crate::der` into the
// certificate structures defined in RFC 5280. Knows nothing about PyO3
// — that translation lives in `crate::pyobj`.

pub mod algorithm;
pub mod certificate;
pub mod extensions;
pub mod name;
pub mod spki;

// Re-exports for the `lib.rs` shim and `pyobj.rs` converters. Other types
// are reachable via their parent module path.
pub use certificate::Certificate;
pub use name::Name;
pub use spki::{PublicKeyAlgorithm, SubjectPublicKeyInfo};
