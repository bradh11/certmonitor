// rust_certinfo/src/x509/certificate.rs
//
// Top-level certificate walker. Implements just enough of RFC 5280 §4.1
// for `certinfo` to expose what it does today via PyO3.
//
// Certificate ::= SEQUENCE {
//     tbsCertificate       TBSCertificate,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signatureValue       BIT STRING
// }
//
// TBSCertificate ::= SEQUENCE {
//     version          [0] EXPLICIT Version DEFAULT v1,
//     serialNumber         CertificateSerialNumber,
//     signature            AlgorithmIdentifier,
//     issuer               Name,
//     validity             Validity,
//     subject              Name,
//     subjectPublicKeyInfo SubjectPublicKeyInfo,
//     issuerUniqueID   [1] IMPLICIT UniqueIdentifier OPTIONAL,
//     subjectUniqueID  [2] IMPLICIT UniqueIdentifier OPTIONAL,
//     extensions       [3] EXPLICIT Extensions OPTIONAL
// }

use crate::der::{tag, time, DerReader};
use crate::error::ParseError;
use crate::x509::{
    algorithm::AlgorithmIdentifier, extensions::Extensions, name::Name, spki::SubjectPublicKeyInfo,
};

#[derive(Debug, Clone, Copy)]
pub struct Validity {
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Certificate<'a> {
    /// Raw serial number value bytes (without the INTEGER tag/length).
    /// Used to render the lowercase-hex "serial_number" Python field.
    pub serial_raw: &'a [u8],
    /// AlgorithmIdentifier of the **outer** signatureAlgorithm field.
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub subject: Name<'a>,
    pub validity: Validity,
    pub spki: SubjectPublicKeyInfo<'a>,
    pub extensions: Extensions<'a>,
}

impl<'a> Certificate<'a> {
    pub fn from_der(der: &'a [u8]) -> Result<Self, ParseError> {
        let mut top = DerReader::new(der);
        let mut cert_inner = top.expect_constructed(tag::TAG_SEQUENCE)?;
        // Whatever the input was, there should be exactly one Certificate.
        top.end()?;

        // tbsCertificate
        let mut tbs = cert_inner.expect_constructed(tag::TAG_SEQUENCE)?;
        // signatureAlgorithm (outer)
        let signature_algorithm = AlgorithmIdentifier::parse(&mut cert_inner)?;
        // signatureValue (we don't read the value, but we do skip it)
        let _sig = cert_inner.read_tlv()?;
        cert_inner.end()?;

        // Inside tbsCertificate
        // Optional [0] EXPLICIT version
        if let Some(tag::CONTEXT_CONSTRUCTED_0) = tbs.peek_tag() {
            // Version is INTEGER 0/1/2; skip the whole [0] wrapper since
            // we don't need the value.
            let _ = tbs.read_tlv()?;
        }
        // serialNumber
        let serial_raw = tbs.expect(tag::TAG_INTEGER)?;
        // signature (inner AlgorithmIdentifier — should equal the outer one;
        // we don't validate equality, just skip)
        let _inner_sig = AlgorithmIdentifier::parse(&mut tbs)?;
        let issuer = Name::parse(&mut tbs)?;
        let validity = parse_validity(&mut tbs)?;
        let subject = Name::parse(&mut tbs)?;
        let spki = SubjectPublicKeyInfo::parse(&mut tbs)?;

        // Optional unique IDs and extensions
        let mut extensions_body: &'a [u8] = &[];
        while !tbs.is_empty() {
            match tbs.peek_tag() {
                Some(0x81) => {
                    // [1] IMPLICIT issuerUniqueID — skip
                    let _ = tbs.read_tlv()?;
                }
                Some(0x82) => {
                    // [2] IMPLICIT subjectUniqueID — skip
                    let _ = tbs.read_tlv()?;
                }
                Some(tag::CONTEXT_CONSTRUCTED_3) => {
                    // [3] EXPLICIT extensions — unwrap once to get the SEQUENCE
                    let mut ext_wrapper = tbs.expect_constructed(tag::CONTEXT_CONSTRUCTED_3)?;
                    let inner = ext_wrapper.expect(tag::TAG_SEQUENCE)?;
                    extensions_body = inner;
                    ext_wrapper.end()?;
                }
                _ => {
                    // Unknown trailing field; advance past it to remain
                    // tolerant of certs with non-standard trailing data.
                    let _ = tbs.read_tlv()?;
                }
            }
        }
        tbs.end()?;

        Ok(Certificate {
            serial_raw,
            signature_algorithm,
            issuer,
            subject,
            validity,
            spki,
            extensions: Extensions::from_body(extensions_body),
        })
    }
}

fn parse_validity(reader: &mut DerReader<'_>) -> Result<Validity, ParseError> {
    let mut inner = reader.expect_constructed(tag::TAG_SEQUENCE)?;
    let nb_tlv = inner.read_tlv()?;
    let na_tlv = inner.read_tlv()?;
    inner.end()?;
    Ok(Validity {
        not_before_unix: time::parse_time(nb_tlv.tag, nb_tlv.value)?,
        not_after_unix: time::parse_time(na_tlv.tag, na_tlv.value)?,
    })
}
