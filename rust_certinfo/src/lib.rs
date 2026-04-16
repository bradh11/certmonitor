// rust_certinfo/src/lib.rs
//
// PyO3 module for the `certinfo` Python extension. This file is a thin
// shim — the actual parsing lives in `crate::der` (DER primitives) and
// `crate::x509` (RFC 5280 structures), with the Python-facing dict
// conversions in `crate::pyobj`.
//
// The PyO3 layer is gated behind the `python` feature (on by default).
// Disabling it (`--no-default-features`) gives you the pure-Rust parser
// with no Python runtime dependency — that's the mode the in-repo
// `fuzz/` crate uses to fuzz `Certificate::from_der` as a standalone
// binary, since the fuzzer isn't loaded by a Python interpreter and
// can't resolve PyO3 symbols at runtime.
//
// Hard guarantees enforced at the crate level:
//   - No `unsafe` anywhere in our code (`forbid(unsafe_code)`).
//   - No panics on malformed input (every parser path returns `Result`).
//   - Zero non-pyo3 runtime dependencies.

#![forbid(unsafe_code)]

mod der;
mod error;
mod x509;

// Public Rust API. The Python wheel doesn't use these — the wheel calls
// the `#[pyfunction]` entry points further down — but the in-repo fuzz
// crate at `fuzz/` does, and any future in-tree Rust consumer (e.g. a
// CLI) can use the same surface.
pub use crate::error::ParseError;
pub use crate::x509::Certificate;

// Everything below is the PyO3 / Python wheel surface. None of it is
// compiled when the `python` feature is off.
#[cfg(feature = "python")]
mod pem;
#[cfg(feature = "python")]
mod pyobj;

#[cfg(feature = "python")]
mod py {
    use super::{pem, pyobj, pyobj::to_py_err, Certificate};
    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyDict};

    /// Parse an X.509 certificate (DER) and return public key info as a dict
    /// `{"algorithm": str, "size": int, "curve": str | None}`.
    ///
    /// For EC keys the `curve` field contains the curve OID (e.g.
    /// `"1.2.840.10045.3.1.7"` for P-256). Earlier builds incorrectly returned
    /// the algorithm OID here.
    #[pyfunction]
    pub(super) fn parse_public_key_info(py: Python<'_>, der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
        let cert = Certificate::from_der(&der_data).map_err(to_py_err)?;
        let dict = pyobj::key_info_dict(py, &cert.spki)?;
        Ok(dict.into())
    }

    /// Extract the SubjectPublicKeyInfo as raw DER bytes.
    #[pyfunction]
    pub(super) fn extract_public_key_der(py: Python<'_>, der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
        let cert = Certificate::from_der(&der_data).map_err(to_py_err)?;
        let bytes = PyBytes::new(py, cert.spki.raw);
        Ok(bytes.into())
    }

    /// Extract the SubjectPublicKeyInfo as a PEM-encoded string.
    #[pyfunction]
    pub(super) fn extract_public_key_pem(der_data: Vec<u8>) -> PyResult<String> {
        let cert = Certificate::from_der(&der_data).map_err(to_py_err)?;
        Ok(pem::wrap_spki_pem(cert.spki.raw))
    }

    /// Parse an entire TLS certificate chain in one call. See
    /// `crate::pyobj::analyze_chain_dict` for the result shape.
    #[pyfunction]
    pub(super) fn analyze_chain(py: Python<'_>, chain_ders: Vec<Vec<u8>>) -> PyResult<Py<PyAny>> {
        let dict: Bound<'_, PyDict> = pyobj::analyze_chain_dict(py, &chain_ders)?;
        Ok(dict.into())
    }

    #[pymodule]
    fn certinfo(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(parse_public_key_info, m)?)?;
        m.add_function(wrap_pyfunction!(extract_public_key_der, m)?)?;
        m.add_function(wrap_pyfunction!(extract_public_key_pem, m)?)?;
        m.add_function(wrap_pyfunction!(analyze_chain, m)?)?;
        Ok(())
    }
}
