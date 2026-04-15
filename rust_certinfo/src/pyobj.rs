// rust_certinfo/src/pyobj.rs
//
// Bridge between the pure-Rust X.509 layer and the PyO3 entry points in
// `lib.rs`. This is the only file in the crate that knows about Python.
// Keeping it isolated means the parser can be reasoned about (and unit
// tested) entirely in Rust, without GIL acquisition.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::error::ParseError;
use crate::x509::{Certificate, Name, PublicKeyAlgorithm, SubjectPublicKeyInfo};

/// Map a `ParseError` to a `PyValueError`. Single seam for error
/// translation; lets the rest of the crate stay PyO3-free.
pub fn to_py_err(err: ParseError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("X.509 parse error: {}", err))
}

/// Build the `{"algorithm": ..., "size": ..., "curve": ...}` dict that
/// `parse_public_key_info` returns. Mirrors the previous shape exactly,
/// **except** the `curve` field for EC keys now correctly contains the
/// curve OID (e.g. `1.2.840.10045.3.1.7`) instead of the algorithm OID.
pub fn key_info_dict<'py>(
    py: Python<'py>,
    spki: &SubjectPublicKeyInfo<'_>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    match spki.parsed() {
        PublicKeyAlgorithm::Rsa { modulus_bits } => {
            dict.set_item("algorithm", "rsaEncryption")?;
            dict.set_item("size", modulus_bits)?;
            dict.set_item("curve", py.None())?;
        }
        PublicKeyAlgorithm::Ec {
            curve_oid,
            key_bits,
        } => {
            dict.set_item("algorithm", "ecPublicKey")?;
            dict.set_item("size", key_bits)?;
            dict.set_item("curve", curve_oid.to_id_string())?;
        }
        PublicKeyAlgorithm::Unknown => {
            dict.set_item("algorithm", "unknown")?;
            dict.set_item("size", 0usize)?;
            dict.set_item("curve", py.None())?;
        }
    }
    Ok(dict)
}

/// Build the per-cert dict used by `analyze_chain`. Mirrors the previous
/// shape exactly so the chain validator and its tests do not need to
/// change.
fn cert_dict<'py>(
    py: Python<'py>,
    position: usize,
    cert: &Certificate<'_>,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("position", position)?;
    d.set_item("subject", name_dict(py, &cert.subject)?)?;
    d.set_item("issuer", name_dict(py, &cert.issuer)?)?;
    d.set_item("not_before_unix", cert.validity.not_before_unix)?;
    d.set_item("not_after_unix", cert.validity.not_after_unix)?;
    d.set_item("serial_number", hex_string(cert.serial_raw))?;

    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    d.set_item("signature_algorithm_weak", is_weak_signature(&sig_oid))?;
    d.set_item("signature_algorithm_oid", sig_oid)?;

    let bc = cert.extensions.basic_constraints().map_err(to_py_err)?;
    d.set_item("is_ca", bc.map(|c| c.ca).unwrap_or(false))?;

    let ski = cert
        .extensions
        .subject_key_identifier()
        .map_err(to_py_err)?
        .map(hex_string);
    let aki = cert
        .extensions
        .authority_key_identifier()
        .map_err(to_py_err)?
        .and_then(|aki| aki.key_identifier.map(hex_string));

    match &ski {
        Some(s) => d.set_item("subject_key_identifier", s)?,
        None => d.set_item("subject_key_identifier", py.None())?,
    };
    match &aki {
        Some(s) => d.set_item("authority_key_identifier", s)?,
        None => d.set_item("authority_key_identifier", py.None())?,
    };

    // Self-signed = subject == issuer (raw DN equality) AND, when both
    // SKI and AKI are present, they match. Mirrors the previous logic.
    let dn_self_match = cert.subject.raw == cert.issuer.raw;
    let ski_aki_ok = match (&ski, &aki) {
        (Some(ski), Some(aki)) => ski == aki,
        _ => true,
    };
    d.set_item("is_self_signed", dn_self_match && ski_aki_ok)?;

    d.set_item("public_key_info", key_info_dict(py, &cert.spki)?)?;

    Ok(d)
}

fn name_dict<'py>(py: Python<'py>, name: &Name<'_>) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    if let Some(cn) = name.common_name() {
        d.set_item("commonName", cn)?;
    }
    if let Some(o) = name.organization() {
        d.set_item("organizationName", o)?;
    }
    if let Some(ou) = name.organizational_unit() {
        d.set_item("organizationalUnitName", ou)?;
    }
    if let Some(c) = name.country() {
        d.set_item("countryName", c)?;
    }
    Ok(d)
}

/// Lowercase hex with no separators. Used for serial number, SKI, AKI.
pub fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn is_weak_signature(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.5"      // sha1WithRSAEncryption
            | "1.2.840.113549.1.1.4" // md5WithRSAEncryption
            | "1.2.840.113549.1.1.2" // md2WithRSAEncryption
            | "1.2.840.10045.4.1"    // ecdsa-with-SHA1
            | "1.2.840.10040.4.3" // dsa-with-sha1
    )
}

/// Build the top-level `analyze_chain` result dict. Mirrors the previous
/// shape so the Python chain validator tests pass unchanged.
pub fn analyze_chain_dict<'py>(
    py: Python<'py>,
    chain_ders: &[Vec<u8>],
) -> PyResult<Bound<'py, PyDict>> {
    // Parse all certs up front so we can compute linkage between adjacent
    // pairs without re-parsing.
    let mut parsed: Vec<Certificate<'_>> = Vec::with_capacity(chain_ders.len());
    for (i, der) in chain_ders.iter().enumerate() {
        let cert = Certificate::from_der(der).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Failed to parse certificate at chain position {}: {}",
                i, e
            ))
        })?;
        parsed.push(cert);
    }

    let top = PyDict::new(py);
    let certs_list = PyList::empty(py);
    let mut terminates_in_self_signed = false;

    // Pre-compute per-cert SKI/AKI hex once so the link loop can reuse
    // them without re-walking extensions.
    let mut per_cert_ski: Vec<Option<String>> = Vec::with_capacity(parsed.len());
    let mut per_cert_aki: Vec<Option<String>> = Vec::with_capacity(parsed.len());

    for (i, cert) in parsed.iter().enumerate() {
        let dict = cert_dict(py, i, cert)?;
        let ski = match dict.get_item("subject_key_identifier")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };
        let aki = match dict.get_item("authority_key_identifier")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };
        per_cert_ski.push(ski);
        per_cert_aki.push(aki);

        if i == parsed.len() - 1 {
            if let Some(v) = dict.get_item("is_self_signed")? {
                terminates_in_self_signed = v.extract::<bool>()?;
            }
        }
        certs_list.append(dict)?;
    }

    let links_list = PyList::empty(py);
    let mut ordered = true;

    for i in 0..parsed.len().saturating_sub(1) {
        let child = &parsed[i];
        let parent = &parsed[i + 1];
        let subject_matches_issuer = child.issuer.raw == parent.subject.raw;
        let aki_matches_ski: Option<bool> = match (&per_cert_aki[i], &per_cert_ski[i + 1]) {
            (Some(a), Some(s)) => Some(a == s),
            _ => None,
        };

        let link = PyDict::new(py);
        link.set_item("subject_matches_issuer", subject_matches_issuer)?;
        match aki_matches_ski {
            Some(v) => link.set_item("aki_matches_ski", v)?,
            None => link.set_item("aki_matches_ski", py.None())?,
        };
        links_list.append(link)?;

        if !subject_matches_issuer {
            ordered = false;
        }
        if let Some(false) = aki_matches_ski {
            ordered = false;
        }
    }

    top.set_item("chain_length", parsed.len())?;
    top.set_item("certs", certs_list)?;
    top.set_item("links", links_list)?;
    top.set_item("ordered", ordered)?;
    top.set_item("terminates_in_self_signed", terminates_in_self_signed)?;
    Ok(top)
}
