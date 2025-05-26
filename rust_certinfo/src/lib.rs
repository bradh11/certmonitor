// src/lib.rs

use base64::{engine::general_purpose, Engine as _};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

/// A small struct to hold the parsed key info in Rust
#[derive(Debug, Clone)]
struct KeyInfo {
    algorithm: String,
    size: usize,
    curve: Option<String>,
}

impl KeyInfo {
    fn new(algorithm: &str, size: usize, curve: Option<String>) -> Self {
        KeyInfo {
            algorithm: algorithm.to_string(),
            size,
            curve,
        }
    }
}

/// Parse the DER bytes of an X.509 certificate and extract public key info.
///
/// Returns a Python dictionary with:
///   - "algorithm": "rsaEncryption" or "ecPublicKey" or "unknown"
///   - "size": the bit length (e.g., 2048 for RSA)
///   - "curve": the curve OID string if EC, or None for RSA
#[pyfunction]
fn parse_public_key_info(der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
    // Parse the certificate from DER
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;

    // Extract SubjectPublicKeyInfo (SPKI)
    let spki = certificate.public_key();

    // spki.parsed() -> Result<PublicKey<'_>, x509_parser::error::X509Error>
    let parsed_pubkey = match spki.parsed() {
        // RSA case
        Ok(PublicKey::RSA(rsa)) => {
            // The RSA modulus is a &[u8], so we get bit-length = len * 8
            let bits = rsa.modulus.len() * 8;
            KeyInfo::new("rsaEncryption", bits, None)
        }
        // EC case
        Ok(PublicKey::EC(ec_point)) => {
            // The bit length of the EC key
            let bits = ec_point.key_size();
            // The EC curve OID is found in spki.algorithm.oid() as a method call
            let curve_oid = spki.algorithm.oid().to_id_string();
            KeyInfo::new("ecPublicKey", bits, Some(curve_oid))
        }
        // Other cases (DSA, Ed25519, etc.) not explicitly handled
        Ok(_) => KeyInfo::new("unknown", 0, None),
        // If the SPKI couldn't be parsed
        Err(_) => KeyInfo::new("unknown", 0, None),
    };

    // Convert KeyInfo into a Python dict
    let py_dict = Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("algorithm", parsed_pubkey.algorithm).unwrap();
        dict.set_item("size", parsed_pubkey.size).unwrap();
        if let Some(curve) = parsed_pubkey.curve {
            dict.set_item("curve", curve).unwrap();
        } else {
            dict.set_item("curve", py.None()).unwrap();
        }
        dict.into()
    });

    Ok(py_dict)
}

/// Extract the public key from a certificate in DER format.
///
/// Returns the DER-encoded SubjectPublicKeyInfo as bytes.
#[pyfunction]
fn extract_public_key_der(der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
    // Parse the certificate from DER
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;

    // Extract SubjectPublicKeyInfo (SPKI) and return its raw DER bytes
    let spki_der = certificate.public_key().raw;

    // Convert to Python bytes object
    Python::with_gil(|py| {
        let py_bytes = pyo3::types::PyBytes::new(py, spki_der);
        Ok(py_bytes.into())
    })
}

/// Extract the public key from a certificate in PEM format.
///
/// Returns the PEM-encoded SubjectPublicKeyInfo as a string.
#[pyfunction]
fn extract_public_key_pem(der_data: Vec<u8>) -> PyResult<String> {
    // Parse the certificate from DER
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;

    // Extract SubjectPublicKeyInfo (SPKI) DER bytes
    let spki_der = certificate.public_key().raw;

    // Encode to base64
    let base64_encoded = general_purpose::STANDARD.encode(spki_der);

    // Format as PEM
    let pem_formatted = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        base64_encoded
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    );

    Ok(pem_formatted)
}

/// The module definition. This tells PyO3 to create a Python module named `certinfo`.
#[pymodule]
fn certinfo(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_public_key_info, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key_pem, m)?)?;
    Ok(())
}
