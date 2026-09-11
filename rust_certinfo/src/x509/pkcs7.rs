// rust_certinfo/src/x509/pkcs7.rs
//
// The one PKCS#7 / CMS shape CertMonitor reads: a certs-only SignedData
// (RFC 5652 §5.1), which is how `.p7b` and `.p7c` files and some
// `caIssuers` responses (RFC 5280 §4.2.2.1) carry a bundle of certificates.
// Nothing here verifies a signature; a certs-only message has no signers,
// and the certificates it carries are checked on their own terms by
// whoever asked for them.
//
// ContentInfo ::= SEQUENCE {
//     contentType  OBJECT IDENTIFIER,          -- id-signedData
//     content      [0] EXPLICIT SignedData }
// SignedData ::= SEQUENCE {
//     version           INTEGER,
//     digestAlgorithms  SET OF AlgorithmIdentifier,
//     encapContentInfo  SEQUENCE,
//     certificates      [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
//     crls              [1] IMPLICIT SET OPTIONAL,
//     signerInfos       SET OF SignerInfo }
// CertificateChoices ::= CHOICE {
//     certificate          Certificate,        -- SEQUENCE, the only one kept
//     extendedCertificate  [0] IMPLICIT ...,   -- obsolete
//     v1AttrCert           [1] IMPLICIT ...,
//     v2AttrCert           [2] IMPLICIT ...,
//     other                [3] IMPLICIT ... }

use crate::der::{oid, tag, DerReader};
use crate::error::ParseError;

/// The raw DER of every `Certificate` in a certs-only SignedData, in the
/// order the message lists them. Attribute certificates and the other
/// `CertificateChoices` alternatives are skipped, and `crls` and
/// `signerInfos` are not examined.
///
/// Fails with `UnexpectedContentType` when the ContentInfo is not
/// signedData, so a bare certificate, whose first element is a SEQUENCE
/// rather than an OID, is never mistaken for a bundle.
pub fn certificates(der: &[u8]) -> Result<Vec<&[u8]>, ParseError> {
    let mut top = DerReader::new(der);
    let mut content_info = top.expect_constructed(tag::TAG_SEQUENCE)?;
    top.end()?;
    if content_info.expect(tag::TAG_OBJECT_IDENTIFIER)? != oid::OID_SIGNED_DATA {
        return Err(ParseError::UnexpectedContentType);
    }
    let mut content = content_info.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
    content_info.end()?;
    let mut signed = content.expect_constructed(tag::TAG_SEQUENCE)?;
    content.end()?;
    let _version = signed.expect(tag::TAG_INTEGER)?;
    let _digest_algorithms = signed.expect(tag::TAG_SET)?;
    let _encapsulated = signed.expect(tag::TAG_SEQUENCE)?;
    let mut found = Vec::new();
    if let Some(tag::CONTEXT_CONSTRUCTED_0) = signed.peek_tag() {
        let mut choices = signed.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
        while !choices.is_empty() {
            let choice = choices.read_tlv()?;
            if choice.tag == tag::TAG_SEQUENCE {
                found.push(choice.raw);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            let bytes: Vec<u8> = content
                .len()
                .to_be_bytes()
                .iter()
                .copied()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// A SignedData with the given `certificates` set body (or none) and
    /// the given contentType.
    fn signed_data(content_type: &[u8], certificates: Option<&[u8]>) -> Vec<u8> {
        let mut body = tlv(tag::TAG_INTEGER, &[1]);
        body.extend(tlv(tag::TAG_SET, &[]));
        // encapContentInfo naming id-data with no content
        body.extend(tlv(
            tag::TAG_SEQUENCE,
            &tlv(
                tag::TAG_OBJECT_IDENTIFIER,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
            ),
        ));
        if let Some(set) = certificates {
            body.extend(tlv(tag::CONTEXT_CONSTRUCTED_0, set));
        }
        body.extend(tlv(tag::TAG_SET, &[])); // signerInfos
        let mut info = tlv(tag::TAG_OBJECT_IDENTIFIER, content_type);
        info.extend(tlv(
            tag::CONTEXT_CONSTRUCTED_0,
            &tlv(tag::TAG_SEQUENCE, &body),
        ));
        tlv(tag::TAG_SEQUENCE, &info)
    }

    #[test]
    fn returns_each_certificate_in_order() {
        let first = tlv(tag::TAG_SEQUENCE, b"leaf");
        let second = tlv(tag::TAG_SEQUENCE, b"issuer");
        let mut set = first.clone();
        set.extend_from_slice(&second);
        let der = signed_data(oid::OID_SIGNED_DATA, Some(&set));
        assert_eq!(certificates(&der).unwrap(), vec![&first[..], &second[..]]);
    }

    #[test]
    fn skips_attribute_certificates_and_other_choices() {
        let cert = tlv(tag::TAG_SEQUENCE, b"cert");
        let mut set = tlv(0xa0, b"extended");
        set.extend(tlv(0xa1, b"v1attr"));
        set.extend_from_slice(&cert);
        set.extend(tlv(0xa2, b"v2attr"));
        set.extend(tlv(0xa3, b"other"));
        let der = signed_data(oid::OID_SIGNED_DATA, Some(&set));
        assert_eq!(certificates(&der).unwrap(), vec![&cert[..]]);
    }

    #[test]
    fn empty_or_absent_certificates_yield_nothing() {
        assert!(certificates(&signed_data(oid::OID_SIGNED_DATA, Some(&[])))
            .unwrap()
            .is_empty());
        assert!(certificates(&signed_data(oid::OID_SIGNED_DATA, None))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn other_content_types_are_refused() {
        let id_data = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
        assert_eq!(
            certificates(&signed_data(&id_data, Some(&[]))).unwrap_err(),
            ParseError::UnexpectedContentType
        );
    }

    #[test]
    fn a_bare_certificate_is_not_a_bundle() {
        // A Certificate starts SEQUENCE { SEQUENCE (tbs) ... }, so the
        // walker meets a SEQUENCE where the contentType OID should be.
        let looks_like_a_cert = tlv(tag::TAG_SEQUENCE, &tlv(tag::TAG_SEQUENCE, b"tbs"));
        assert!(matches!(
            certificates(&looks_like_a_cert).unwrap_err(),
            ParseError::UnexpectedTag { .. }
        ));
    }

    #[test]
    fn malformed_input_errors_instead_of_panicking() {
        assert!(certificates(&[]).is_err());
        assert!(certificates(&[0x30, 0x80, 0x00, 0x00]).is_err()); // indefinite length
        assert!(certificates(&[0x30, 0x05, 0x06, 0x01, 0x2a]).is_err());
        let mut truncated = signed_data(oid::OID_SIGNED_DATA, Some(&tlv(tag::TAG_SEQUENCE, b"x")));
        truncated.truncate(truncated.len() - 3);
        assert!(certificates(&truncated).is_err());
    }
}
