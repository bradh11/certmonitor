// rust_certinfo/src/lib.rs
//
// PyO3 module for the `certinfo` Python extension. This file is a thin
// shim, the actual parsing lives in `crate::der` (DER primitives) and
// `crate::x509` (RFC 5280 structures), with the Python-facing dict
// conversions in `crate::pyobj`.
//
// The PyO3 layer is gated behind the `python` feature (on by default).
// Disabling it (`--no-default-features`) gives you the pure-Rust parser
// with no Python runtime dependency, that's the mode the in-repo
// `fuzz/` crate uses to fuzz `Certificate::from_der` as a standalone
// binary, since the fuzzer isn't loaded by a Python interpreter and
// can't resolve PyO3 symbols at runtime.
//
// Hard guarantees enforced at the crate level:
//   - No `unsafe` anywhere in our code (`forbid(unsafe_code)`).
//   - No panics on malformed input (every parser path returns `Result`).
//   - Zero non-pyo3 runtime dependencies.

#![forbid(unsafe_code)]

mod crypto;
mod der;
mod error;
mod pq_algorithms;
// Public so the in-repo fuzz crate (and the upcoming probe, #33) can
// reach the parsers; deliberately NOT exported to Python yet, the
// PyO3 surface for TLS probing lands with tls/probe.rs (#33).
pub mod tls;
mod x509;

// Public Rust API. The Python wheel doesn't use these, the wheel calls
// the `#[pyfunction]` entry points further down, but the in-repo fuzz
// crate at `fuzz/` does, and any future in-tree Rust consumer (e.g. a
// CLI) can use the same surface.
pub use crate::crypto::bigint::BigUint;
pub use crate::crypto::eddsa::{verify as verify_eddsa, EdCurve};
pub use crate::crypto::rsa::PssParameters;
pub use crate::crypto::VerifyError;
pub use crate::error::ParseError;
pub use crate::x509::crl::Crl;
pub use crate::x509::ocsp::OcspResponse;
pub use crate::x509::verify::verify_signature;
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
    /// `"1.2.840.10045.3.1.7"` for P-256).
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

    /// Return the post-quantum algorithm registry as a list of dicts
    /// `{"dotted": str, "name": str, "composite": bool}`. Python-side
    /// consumers (e.g. the `key_info` validator) derive their PQ name
    /// sets from this, so the table in `pq_algorithms.rs` stays the
    /// single source of truth.
    #[pyfunction]
    pub(super) fn pq_algorithms(py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(pyobj::pq_algorithms_list(py)?.into())
    }

    /// Probe a TLS 1.3 server for its key-exchange group. Opens a TCP
    /// connection to `host` (offering `server_name`, or `host`, as SNI),
    /// runs the optional `starttls` preamble (smtp, imap, pop3, ftp,
    /// postgres, ldap),
    /// sends one ClientHello offering X25519MLKEM768, reads
    /// the ServerHello, extracts the negotiated (or HRR-requested)
    /// group, and closes, no crypto, no certificate validation.
    ///
    /// Returns a dict in every terminal state (never raises for network
    /// or protocol conditions); see `pyobj::probe_result_dict` for the
    /// shape. The socket work runs with the GIL released.
    #[pyfunction]
    #[pyo3(signature = (host, port=443, timeout_ms=10000, server_name=None, starttls=None, proxy=None))]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(super) fn probe_tls_handshake(
        py: Python<'_>,
        host: &str,
        port: u16,
        timeout_ms: u64,
        server_name: Option<&str>,
        starttls: Option<&str>,
        proxy: Option<(String, String, u16, Option<String>, Option<String>)>,
    ) -> PyResult<Py<PyAny>> {
        let timeout = std::time::Duration::from_millis(timeout_ms);
        // `proxy` is a ProxyConfig tuple: (scheme, host, port, username, password).
        let proxy =
            proxy.map(
                |(scheme, host, port, username, password)| crate::tls::proxy::Proxy {
                    scheme,
                    host,
                    port,
                    username,
                    password,
                },
            );
        // Release the GIL for the blocking socket work so concurrent
        // scans don't serialize on the probe. (`detach` is pyo3 0.29's
        // rename of the former `allow_threads`.)
        let result = py.detach(|| {
            crate::tls::probe::probe(host, port, server_name, starttls, proxy.as_ref(), timeout)
        });
        Ok(pyobj::probe_result_dict(py, &result)?.into())
    }

    /// Parse a DER OCSP response (RFC 6960) into a dict: `response_status`,
    /// the responder id, `produced_at`, per-certificate `responses`, and
    /// the signed bytes and signature for verification. Never panics.
    #[pyfunction]
    pub(super) fn parse_ocsp_response(py: Python<'_>, der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
        let response = crate::x509::ocsp::OcspResponse::from_der(&der_data).map_err(to_py_err)?;
        Ok(pyobj::ocsp_response_dict(py, &response)?.into())
    }

    /// The inputs an OCSP CertID is built from, or `None` when `issuer_der`
    /// did not issue `leaf_der`.
    #[pyfunction]
    pub(super) fn ocsp_cert_id_inputs(
        py: Python<'_>,
        leaf_der: Vec<u8>,
        issuer_der: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        match crate::x509::ocsp::cert_id_inputs(&leaf_der, &issuer_der).map_err(to_py_err)? {
            Some(inputs) => Ok(pyobj::cert_id_inputs_dict(py, &inputs)?.into()),
            None => Ok(py.None()),
        }
    }

    /// A DER CRL's issuer, validity window, size, scope extensions, and any
    /// critical extensions CertMonitor cannot process.
    #[pyfunction]
    pub(super) fn crl_info(py: Python<'_>, der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
        let crl = crate::x509::crl::Crl::from_der(&der_data).map_err(to_py_err)?;
        Ok(pyobj::crl_info_dict(py, &crl)?.into())
    }

    /// The CRL entry for a serial number (raw INTEGER bytes), or `None`.
    #[pyfunction]
    pub(super) fn crl_lookup(
        py: Python<'_>,
        der_data: Vec<u8>,
        serial_number: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        let crl = crate::x509::crl::Crl::from_der(&der_data).map_err(to_py_err)?;
        match pyobj::crl_lookup_dict(py, &crl, &serial_number)? {
            Some(entry) => Ok(entry.into()),
            None => Ok(py.None()),
        }
    }

    /// The hash algorithm name (`sha1`, `sha256`, `sha384`, `sha512`) a
    /// signature algorithm OID implies, or `None` if the algorithm is not
    /// one CertMonitor can verify.
    #[pyfunction]
    pub(super) fn signature_hash(algorithm: &str) -> Option<&'static str> {
        crate::x509::verify::signature_algorithm(algorithm).map(|(_, hash)| hash.name())
    }

    /// Verify `signature` over `digest` with the public key in `spki_der`.
    /// Returns False for a signature that does not verify; raises
    /// `ValueError` when the algorithm or key is unsupported or malformed.
    #[pyfunction]
    pub(super) fn verify_signature(
        py: Python<'_>,
        algorithm: &str,
        digest: Vec<u8>,
        signature: Vec<u8>,
        spki_der: Vec<u8>,
    ) -> PyResult<bool> {
        py.detach(|| {
            crate::x509::verify::verify_signature(algorithm, &digest, &signature, &spki_der)
        })
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// The pieces needed to verify a certificate's signature and to use it
    /// as a signer: `tbs`, `signature`, `signature_algorithm`,
    /// `signature_algorithm_params`, `spki`, `key_bits`, `subject`,
    /// `subject_der`, `issuer_der`, `not_before`, `not_after`, `key_usage`
    /// (bit names, or `None` when absent), and `extended_key_usage`.
    #[pyfunction]
    pub(super) fn certificate_signature_parts(
        py: Python<'_>,
        der_data: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        let cert = Certificate::from_der(&der_data).map_err(to_py_err)?;
        Ok(pyobj::certificate_signature_parts_dict(py, &cert)?.into())
    }

    /// The RSASSA-PSS encoded message `EM` and the modulus's bit length, as
    /// a `(bytes, int)` tuple. `EM` is `emLen = ceil((modBits - 1) / 8)`
    /// octets (RFC 8017 §8.1.2 step 2.c), which the PSS padding check in
    /// Python consumes as it stands. Raises ValueError when the key is not
    /// RSA, is outside the supported bounds, the signature is the wrong
    /// length or out of range, or the recovered value needs more than
    /// `modBits - 1` bits.
    #[pyfunction]
    pub(super) fn rsa_pss_encoded_message(
        py: Python<'_>,
        signature: Vec<u8>,
        spki_der: Vec<u8>,
    ) -> PyResult<Py<PyAny>> {
        let (em, mod_bits) = py
            .detach(|| {
                let mut reader = crate::der::DerReader::new(&spki_der);
                let spki = crate::x509::spki::SubjectPublicKeyInfo::parse(&mut reader)
                    .map_err(|_| crate::crypto::VerifyError::Malformed("SubjectPublicKeyInfo"))?;
                match spki.parsed() {
                    crate::x509::spki::PublicKeyAlgorithm::Rsa { .. } => {
                        let key =
                            crate::crypto::rsa::RsaPublicKey::from_der(spki.subject_public_key)?;
                        crate::crypto::rsa::pss_encoded_message(&key, &signature)
                    }
                    _ => Err(crate::crypto::VerifyError::Unsupported(
                        "non-RSA key for RSA public operation".to_string(),
                    )),
                }
            })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok((PyBytes::new(py, &em), mod_bits).into_pyobject(py)?.into())
    }

    /// Verify a PureEdDSA signature (RFC 8032 §5.1.7, §5.2.7). `curve` is
    /// `"Ed25519"` or `"Ed448"`, `public_key` the raw `subjectPublicKey`
    /// bits, `r` and `s` the two halves of the signature, and `k` the
    /// challenge hash `H(R || A || M)`, which the caller computes so the
    /// hashing stays in Python. Returns False for a signature that is
    /// simply wrong; raises `ValueError` for an unknown curve name or for
    /// inputs of the wrong length or a public key that does not decode.
    #[pyfunction]
    pub(super) fn eddsa_verify(
        py: Python<'_>,
        curve: &str,
        public_key: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
        k: Vec<u8>,
    ) -> PyResult<bool> {
        let curve = match curve {
            "Ed25519" => crate::crypto::eddsa::EdCurve::Ed25519,
            "Ed448" => crate::crypto::eddsa::EdCurve::Ed448,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unsupported EdDSA curve {other}"
                )))
            }
        };
        py.detach(|| crate::crypto::eddsa::verify(curve, &public_key, &r, &s, &k))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Parse a bare DER SubjectPublicKeyInfo into
    /// `{"algorithm": str, "size": int, "curve": str | None,
    /// "key_bits": bytes, "algorithm_params": bytes | None}`. The first
    /// three keys are exactly what `parse_public_key_info` reports, which
    /// takes a whole certificate; this takes the SubjectPublicKeyInfo on
    /// its own, which is what a signature check has in hand, and adds the
    /// raw `subjectPublicKey` bits along with the raw
    /// `AlgorithmIdentifier.parameters` TLV (`None` when absent or NULL),
    /// which is where an id-RSASSA-PSS key carries the restrictions RFC
    /// 4055 §3.3 puts on it. Raises `ValueError` when the
    /// SubjectPublicKeyInfo does not parse.
    #[pyfunction]
    pub(super) fn parse_spki(py: Python<'_>, spki_der: Vec<u8>) -> PyResult<Py<PyAny>> {
        let mut reader = crate::der::DerReader::new(&spki_der);
        let spki = crate::x509::spki::SubjectPublicKeyInfo::parse(&mut reader).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("malformed SubjectPublicKeyInfo")
        })?;
        let dict = pyobj::key_info_dict(py, &spki)?;
        dict.set_item("key_bits", PyBytes::new(py, spki.subject_public_key))?;
        match spki.algorithm.parameters {
            Some(params) => dict.set_item("algorithm_params", PyBytes::new(py, params))?,
            None => dict.set_item("algorithm_params", py.None())?,
        }
        Ok(dict.into())
    }

    /// Parse RSASSA-PSS-params (RFC 4055) into hashlib names and lengths:
    /// `hash`, `mgf_hash`, `salt_length`, and `trailer_field`. `None`
    /// parameters yield the RFC 4055 defaults (SHA-1, MGF1 with SHA-1, a
    /// 20-byte salt, trailer field 1). Raises `ValueError` for a mask
    /// generation function other than MGF1 or a hash outside SHA-1,
    /// SHA-256, SHA-384, and SHA-512.
    #[pyfunction]
    pub(super) fn rsa_pss_parameters(
        py: Python<'_>,
        params_der: Option<Vec<u8>>,
    ) -> PyResult<Py<PyAny>> {
        let params = py
            .detach(|| crate::crypto::rsa::PssParameters::parse(params_der.as_deref()))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let d = PyDict::new(py);
        d.set_item("hash", params.hash.name())?;
        d.set_item("mgf_hash", params.mgf_hash.name())?;
        d.set_item("salt_length", params.salt_length)?;
        d.set_item("trailer_field", params.trailer_field)?;
        Ok(d.into())
    }

    #[pymodule]
    fn certinfo(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(parse_public_key_info, m)?)?;
        m.add_function(wrap_pyfunction!(extract_public_key_der, m)?)?;
        m.add_function(wrap_pyfunction!(extract_public_key_pem, m)?)?;
        m.add_function(wrap_pyfunction!(analyze_chain, m)?)?;
        m.add_function(wrap_pyfunction!(pq_algorithms, m)?)?;
        m.add_function(wrap_pyfunction!(probe_tls_handshake, m)?)?;
        m.add_function(wrap_pyfunction!(parse_ocsp_response, m)?)?;
        m.add_function(wrap_pyfunction!(ocsp_cert_id_inputs, m)?)?;
        m.add_function(wrap_pyfunction!(crl_info, m)?)?;
        m.add_function(wrap_pyfunction!(crl_lookup, m)?)?;
        m.add_function(wrap_pyfunction!(signature_hash, m)?)?;
        m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
        m.add_function(wrap_pyfunction!(certificate_signature_parts, m)?)?;
        m.add_function(wrap_pyfunction!(rsa_pss_encoded_message, m)?)?;
        m.add_function(wrap_pyfunction!(rsa_pss_parameters, m)?)?;
        m.add_function(wrap_pyfunction!(eddsa_verify, m)?)?;
        m.add_function(wrap_pyfunction!(parse_spki, m)?)?;
        Ok(())
    }
}
