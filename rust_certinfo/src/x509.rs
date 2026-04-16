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

// `Certificate` is always public — it's the entry point both the PyO3
// shim and the in-repo fuzz crate use.
pub use certificate::Certificate;

// These re-exports only serve `pyobj.rs`, which is gated behind the
// `python` feature. Without the gate, `cargo build --no-default-features`
// (the fuzz crate's mode) warns they're unused. Gating them matches the
// gate on their only consumer.
#[cfg(feature = "python")]
pub use name::Name;
#[cfg(feature = "python")]
pub use spki::{PublicKeyAlgorithm, SubjectPublicKeyInfo};
