// src/lib.rs

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

// Minimal RFC 4648 base64 encoder (standard alphabet, with padding).
// Encode-only; we only need it to wrap SPKI DER into PEM. Kept inline so
// the crate has no runtime dependency on the `base64` crate.
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

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

fn extract_key_info(cert: &X509Certificate) -> KeyInfo {
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = rsa.modulus.len() * 8;
            KeyInfo::new("rsaEncryption", bits, None)
        }
        Ok(PublicKey::EC(ec_point)) => {
            let bits = ec_point.key_size();
            let curve_oid = spki.algorithm.oid().to_id_string();
            KeyInfo::new("ecPublicKey", bits, Some(curve_oid))
        }
        Ok(_) => KeyInfo::new("unknown", 0, None),
        Err(_) => KeyInfo::new("unknown", 0, None),
    }
}

fn key_info_to_pydict<'py>(py: Python<'py>, key_info: &KeyInfo) -> Bound<'py, PyDict> {
    let dict = PyDict::new(py);
    dict.set_item("algorithm", &key_info.algorithm).unwrap();
    dict.set_item("size", key_info.size).unwrap();
    match &key_info.curve {
        Some(curve) => dict.set_item("curve", curve).unwrap(),
        None => dict.set_item("curve", py.None()).unwrap(),
    }
    dict
}

/// Parse the DER bytes of an X.509 certificate and extract public key info.
///
/// Returns a Python dictionary with:
///   - "algorithm": "rsaEncryption" or "ecPublicKey" or "unknown"
///   - "size": the bit length (e.g., 2048 for RSA)
///   - "curve": the curve OID string if EC, or None for RSA
#[pyfunction]
fn parse_public_key_info(der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;
    let key_info = extract_key_info(&certificate);

    let py_dict = Python::with_gil(|py| {
        let dict = key_info_to_pydict(py, &key_info);
        dict.into()
    });

    Ok(py_dict)
}

/// Extract the public key from a certificate in DER format.
///
/// Returns the DER-encoded SubjectPublicKeyInfo as bytes.
#[pyfunction]
fn extract_public_key_der(der_data: Vec<u8>) -> PyResult<Py<PyAny>> {
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;

    let spki_der = certificate.public_key().raw;

    Python::with_gil(|py| {
        let py_bytes = PyBytes::new(py, spki_der);
        Ok(py_bytes.into())
    })
}

/// Extract the public key from a certificate in PEM format.
///
/// Returns the PEM-encoded SubjectPublicKeyInfo as a string.
#[pyfunction]
fn extract_public_key_pem(der_data: Vec<u8>) -> PyResult<String> {
    let (_, certificate) = X509Certificate::from_der(&der_data)
        .map_err(|_| PyValueError::new_err("Failed to parse X.509 certificate"))?;

    let spki_der = certificate.public_key().raw;
    let encoded = b64_encode(spki_der);

    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        wrapped
    ))
}

fn collect_name_fields(name: &X509Name) -> Vec<(&'static str, String)> {
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    if let Some(s) = name.iter_common_name().next().and_then(|a| a.as_str().ok()) {
        fields.push(("commonName", s.to_string()));
    }
    if let Some(s) = name
        .iter_organization()
        .next()
        .and_then(|a| a.as_str().ok())
    {
        fields.push(("organizationName", s.to_string()));
    }
    if let Some(s) = name
        .iter_organizational_unit()
        .next()
        .and_then(|a| a.as_str().ok())
    {
        fields.push(("organizationalUnitName", s.to_string()));
    }
    if let Some(s) = name.iter_country().next().and_then(|a| a.as_str().ok()) {
        fields.push(("countryName", s.to_string()));
    }
    fields
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn is_weak_signature(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.5"      // sha1WithRSAEncryption
            | "1.2.840.113549.1.1.4" // md5WithRSAEncryption
            | "1.2.840.113549.1.1.2" // md2WithRSAEncryption
            | "1.2.840.10045.4.1"    // ecdsa-with-SHA1
            | "1.2.840.10040.4.3" // dsa-with-sha1
    )
}

struct CertData {
    subject_raw: Vec<u8>,
    issuer_raw: Vec<u8>,
    subject_fields: Vec<(&'static str, String)>,
    issuer_fields: Vec<(&'static str, String)>,
    not_before_unix: i64,
    not_after_unix: i64,
    serial_hex: String,
    sig_oid: String,
    is_ca: bool,
    ski: Option<String>,
    aki: Option<String>,
    key_info: KeyInfo,
}

fn extract_cert_data(cert: &X509Certificate) -> CertData {
    let mut ski: Option<String> = None;
    let mut aki: Option<String> = None;
    let mut is_ca = false;

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => {
                ski = Some(hex_string(k.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                aki = a.key_identifier.as_ref().map(|k| hex_string(k.0));
            }
            ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
            }
            _ => {}
        }
    }

    CertData {
        subject_raw: cert.subject().as_raw().to_vec(),
        issuer_raw: cert.issuer().as_raw().to_vec(),
        subject_fields: collect_name_fields(cert.subject()),
        issuer_fields: collect_name_fields(cert.issuer()),
        not_before_unix: cert.validity().not_before.timestamp(),
        not_after_unix: cert.validity().not_after.timestamp(),
        serial_hex: hex_string(cert.raw_serial()),
        sig_oid: cert.signature_algorithm.algorithm.to_id_string(),
        is_ca,
        ski,
        aki,
        key_info: extract_key_info(cert),
    }
}

/// Parse a full TLS certificate chain and report per-cert details plus
/// adjacent-pair linkage. Structural validation only — no cryptographic
/// signature verification (which would require pulling in a crypto crate).
///
/// Input: `chain_ders` is an ordered list of DER-encoded X.509 certificates,
/// leaf first. Typically from `SSLSocket.get_verified_chain()` on Python 3.13+
/// or `SSLSocket._sslobj.get_unverified_chain()` on 3.10–3.12.
///
/// Returns a Python dictionary shaped like:
///   {
///     "chain_length": int,
///     "certs": [ { per-cert details... }, ... ],
///     "links": [ { subject_matches_issuer, aki_matches_ski }, ... ],
///     "ordered": bool,
///     "terminates_in_self_signed": bool,
///   }
#[pyfunction]
fn analyze_chain(chain_ders: Vec<Vec<u8>>) -> PyResult<Py<PyAny>> {
    let mut data: Vec<CertData> = Vec::with_capacity(chain_ders.len());
    for (i, der) in chain_ders.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der).map_err(|_| {
            PyValueError::new_err(format!(
                "Failed to parse certificate at chain position {}",
                i
            ))
        })?;
        data.push(extract_cert_data(&cert));
    }

    Python::with_gil(|py| {
        let top = PyDict::new(py);
        let certs_list = PyList::empty(py);
        let mut terminates_in_self_signed = false;

        for (i, cd) in data.iter().enumerate() {
            let cert_dict = PyDict::new(py);
            cert_dict.set_item("position", i).unwrap();

            let subject_dict = PyDict::new(py);
            for (k, v) in &cd.subject_fields {
                subject_dict.set_item(*k, v).unwrap();
            }
            cert_dict.set_item("subject", subject_dict).unwrap();

            let issuer_dict = PyDict::new(py);
            for (k, v) in &cd.issuer_fields {
                issuer_dict.set_item(*k, v).unwrap();
            }
            cert_dict.set_item("issuer", issuer_dict).unwrap();

            cert_dict
                .set_item("not_before_unix", cd.not_before_unix)
                .unwrap();
            cert_dict
                .set_item("not_after_unix", cd.not_after_unix)
                .unwrap();
            cert_dict.set_item("serial_number", &cd.serial_hex).unwrap();
            cert_dict
                .set_item("signature_algorithm_oid", &cd.sig_oid)
                .unwrap();
            cert_dict
                .set_item("signature_algorithm_weak", is_weak_signature(&cd.sig_oid))
                .unwrap();
            cert_dict.set_item("is_ca", cd.is_ca).unwrap();

            match &cd.ski {
                Some(v) => cert_dict.set_item("subject_key_identifier", v).unwrap(),
                None => cert_dict
                    .set_item("subject_key_identifier", py.None())
                    .unwrap(),
            }
            match &cd.aki {
                Some(v) => cert_dict.set_item("authority_key_identifier", v).unwrap(),
                None => cert_dict
                    .set_item("authority_key_identifier", py.None())
                    .unwrap(),
            }

            let dn_self_match = cd.subject_raw == cd.issuer_raw;
            let ski_aki_ok = match (&cd.ski, &cd.aki) {
                (Some(ski), Some(aki)) => ski == aki,
                _ => true,
            };
            let is_self_signed = dn_self_match && ski_aki_ok;
            cert_dict
                .set_item("is_self_signed", is_self_signed)
                .unwrap();

            cert_dict
                .set_item("public_key_info", key_info_to_pydict(py, &cd.key_info))
                .unwrap();

            if i == data.len() - 1 && is_self_signed {
                terminates_in_self_signed = true;
            }

            certs_list.append(cert_dict).unwrap();
        }

        let links_list = PyList::empty(py);
        let mut ordered = true;

        for i in 0..data.len().saturating_sub(1) {
            let child = &data[i];
            let parent = &data[i + 1];

            let subject_matches_issuer = child.issuer_raw == parent.subject_raw;
            let aki_matches_ski: Option<bool> = match (&child.aki, &parent.ski) {
                (Some(a), Some(s)) => Some(a == s),
                _ => None,
            };

            let link = PyDict::new(py);
            link.set_item("subject_matches_issuer", subject_matches_issuer)
                .unwrap();
            match aki_matches_ski {
                Some(v) => link.set_item("aki_matches_ski", v).unwrap(),
                None => link.set_item("aki_matches_ski", py.None()).unwrap(),
            }
            links_list.append(link).unwrap();

            if !subject_matches_issuer {
                ordered = false;
            }
            if let Some(false) = aki_matches_ski {
                ordered = false;
            }
        }

        top.set_item("chain_length", data.len()).unwrap();
        top.set_item("certs", certs_list).unwrap();
        top.set_item("links", links_list).unwrap();
        top.set_item("ordered", ordered).unwrap();
        top.set_item("terminates_in_self_signed", terminates_in_self_signed)
            .unwrap();

        Ok(top.into())
    })
}

/// The module definition. This tells PyO3 to create a Python module named `certinfo`.
#[pymodule]
fn certinfo(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_public_key_info, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_chain, m)?)?;
    Ok(())
}
