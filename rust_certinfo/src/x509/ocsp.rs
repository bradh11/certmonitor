// rust_certinfo/src/x509/ocsp.rs
//
// OCSP (RFC 6960) structures for the revocation validator: the response a
// responder returns, and the inputs a request's CertID is built from.
// Parsing only; signature verification lives in `crate::x509::verify`
// once it lands, and until then the Python layer reports responses as
// unverified.
//
// OCSPResponse ::= SEQUENCE {
//     responseStatus  ENUMERATED,
//     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
// ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
// BasicOCSPResponse ::= SEQUENCE {
//     tbsResponseData      ResponseData,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signature            BIT STRING,
//     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
// ResponseData ::= SEQUENCE {
//     version        [0] EXPLICIT Version DEFAULT v1,
//     responderID    CHOICE { byName [1] Name, byKey [2] OCTET STRING },
//     producedAt     GeneralizedTime,
//     responses      SEQUENCE OF SingleResponse,
//     responseExtensions [1] EXPLICIT Extensions OPTIONAL }
// SingleResponse ::= SEQUENCE {
//     certID       CertID,
//     certStatus   CHOICE { good [0] IMPLICIT NULL,
//                           revoked [1] IMPLICIT RevokedInfo,
//                           unknown [2] IMPLICIT NULL },
//     thisUpdate   GeneralizedTime,
//     nextUpdate   [0] EXPLICIT GeneralizedTime OPTIONAL,
//     singleExtensions [1] EXPLICIT Extensions OPTIONAL }

use crate::der::{tag, time, DerReader, Oid};
use crate::error::ParseError;
use crate::x509::{algorithm::AlgorithmIdentifier, name::Name, Certificate};

/// id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    Other(u8),
}

impl ResponseStatus {
    pub fn as_str(&self) -> String {
        match self {
            Self::Successful => "successful".into(),
            Self::MalformedRequest => "malformed_request".into(),
            Self::InternalError => "internal_error".into(),
            Self::TryLater => "try_later".into(),
            Self::SigRequired => "sig_required".into(),
            Self::Unauthorized => "unauthorized".into(),
            Self::Other(code) => format!("status_{code}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

impl CertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }
}

/// CRLReason (RFC 5280 §5.3.1), shared with CRL entries.
pub fn crl_reason_name(code: u8) -> String {
    match code {
        0 => "unspecified".into(),
        1 => "key_compromise".into(),
        2 => "ca_compromise".into(),
        3 => "affiliation_changed".into(),
        4 => "superseded".into(),
        5 => "cessation_of_operation".into(),
        6 => "certificate_hold".into(),
        8 => "remove_from_crl".into(),
        9 => "privilege_withdrawn".into(),
        10 => "aa_compromise".into(),
        other => format!("reason_{other}"),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CertId<'a> {
    pub hash_algorithm: Oid<'a>,
    pub issuer_name_hash: &'a [u8],
    pub issuer_key_hash: &'a [u8],
    /// Raw INTEGER value bytes of the serial number.
    pub serial_raw: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub status: CertStatus,
    pub this_update_unix: i64,
    pub next_update_unix: Option<i64>,
    pub revocation_time_unix: Option<i64>,
    pub revocation_reason: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum ResponderId<'a> {
    ByName(Name<'a>),
    ByKey(&'a [u8]),
}

#[derive(Debug, Clone)]
pub struct OcspResponse<'a> {
    pub status: ResponseStatus,
    /// Everything below is present only for a successful basic response.
    pub responder_id: Option<ResponderId<'a>>,
    pub produced_at_unix: Option<i64>,
    pub responses: Vec<SingleResponse<'a>>,
    /// Raw DER of ResponseData, the bytes the responder signed.
    pub tbs_response_data: Option<&'a [u8]>,
    pub signature_algorithm: Option<AlgorithmIdentifier<'a>>,
    /// Signature BIT STRING contents after the unused-bits byte.
    pub signature: Option<&'a [u8]>,
    /// DER of each certificate the responder attached (delegated responders).
    pub certs: Vec<&'a [u8]>,
}

impl<'a> OcspResponse<'a> {
    pub fn from_der(der: &'a [u8]) -> Result<Self, ParseError> {
        let mut top = DerReader::new(der);
        let mut outer = top.expect_constructed(tag::TAG_SEQUENCE)?;
        top.end()?;

        let status_raw = outer.expect(TAG_ENUMERATED)?;
        let status = match status_raw {
            [0] => ResponseStatus::Successful,
            [1] => ResponseStatus::MalformedRequest,
            [2] => ResponseStatus::InternalError,
            [3] => ResponseStatus::TryLater,
            [5] => ResponseStatus::SigRequired,
            [6] => ResponseStatus::Unauthorized,
            [code] => ResponseStatus::Other(*code),
            _ => return Err(ParseError::IntegerOverflow),
        };
        let mut response = OcspResponse {
            status,
            responder_id: None,
            produced_at_unix: None,
            responses: Vec::new(),
            tbs_response_data: None,
            signature_algorithm: None,
            signature: None,
            certs: Vec::new(),
        };
        if outer.is_empty() {
            return Ok(response);
        }

        // [0] EXPLICIT ResponseBytes
        let mut wrapper = outer.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
        outer.end()?;
        let mut response_bytes = wrapper.expect_constructed(tag::TAG_SEQUENCE)?;
        wrapper.end()?;
        let response_type = response_bytes.expect(tag::TAG_OBJECT_IDENTIFIER)?;
        if response_type != OID_OCSP_BASIC {
            // Not a basic response: report the status but nothing else.
            return Ok(response);
        }
        let basic_der = response_bytes.expect(tag::TAG_OCTET_STRING)?;
        response_bytes.end()?;

        // BasicOCSPResponse
        let mut basic_top = DerReader::new(basic_der);
        let mut basic = basic_top.expect_constructed(tag::TAG_SEQUENCE)?;
        basic_top.end()?;
        let tbs_tlv = basic.read_tlv()?;
        if tbs_tlv.tag != tag::TAG_SEQUENCE {
            return Err(ParseError::UnexpectedTag {
                expected: tag::TAG_SEQUENCE,
                got: tbs_tlv.tag,
            });
        }
        response.tbs_response_data = Some(tbs_tlv.raw);
        response.signature_algorithm = Some(AlgorithmIdentifier::parse(&mut basic)?);
        let signature_bits = basic.expect(tag::TAG_BIT_STRING)?;
        response.signature = Some(unwrap_bit_string(signature_bits)?);
        if !basic.is_empty() {
            let mut certs_wrapper = basic.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
            let mut certs = certs_wrapper.expect_constructed(tag::TAG_SEQUENCE)?;
            certs_wrapper.end()?;
            while !certs.is_empty() {
                response.certs.push(certs.read_tlv()?.raw);
            }
        }
        basic.end()?;

        // ResponseData
        let mut data = DerReader::new(tbs_tlv.value);
        if let Some(tag::CONTEXT_CONSTRUCTED_0) = data.peek_tag() {
            let _version = data.read_tlv()?;
        }
        let responder = data.read_tlv()?;
        response.responder_id = Some(match responder.tag {
            0xa1 => {
                let mut inner = DerReader::new(responder.value);
                let name = Name::parse(&mut inner)?;
                inner.end()?;
                ResponderId::ByName(name)
            }
            0xa2 => {
                let mut inner = DerReader::new(responder.value);
                let key_hash = inner.expect(tag::TAG_OCTET_STRING)?;
                inner.end()?;
                ResponderId::ByKey(key_hash)
            }
            got => {
                return Err(ParseError::UnexpectedTag {
                    expected: 0xa1,
                    got,
                })
            }
        });
        let produced = data.read_tlv()?;
        response.produced_at_unix = Some(time::parse_time(produced.tag, produced.value)?);
        let mut list = data.expect_constructed(tag::TAG_SEQUENCE)?;
        while !list.is_empty() {
            response.responses.push(parse_single_response(&mut list)?);
        }
        // responseExtensions [1] EXPLICIT OPTIONAL: nothing we need.
        while !data.is_empty() {
            let _ = data.read_tlv()?;
        }
        Ok(response)
    }
}

const TAG_ENUMERATED: u8 = 0x0a;

fn unwrap_bit_string(bits: &[u8]) -> Result<&[u8], ParseError> {
    match bits.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(ParseError::InvalidBitString),
    }
}

fn parse_cert_id<'a>(reader: &mut DerReader<'a>) -> Result<CertId<'a>, ParseError> {
    let mut inner = reader.expect_constructed(tag::TAG_SEQUENCE)?;
    let hash_algorithm = AlgorithmIdentifier::parse(&mut inner)?.algorithm;
    let issuer_name_hash = inner.expect(tag::TAG_OCTET_STRING)?;
    let issuer_key_hash = inner.expect(tag::TAG_OCTET_STRING)?;
    let serial_raw = inner.expect(tag::TAG_INTEGER)?;
    inner.end()?;
    Ok(CertId {
        hash_algorithm,
        issuer_name_hash,
        issuer_key_hash,
        serial_raw,
    })
}

fn parse_single_response<'a>(reader: &mut DerReader<'a>) -> Result<SingleResponse<'a>, ParseError> {
    let mut inner = reader.expect_constructed(tag::TAG_SEQUENCE)?;
    let cert_id = parse_cert_id(&mut inner)?;
    let status_tlv = inner.read_tlv()?;
    let mut revocation_time_unix = None;
    let mut revocation_reason = None;
    let status = match status_tlv.tag {
        0x80 => CertStatus::Good,
        0x82 => CertStatus::Unknown,
        0xa1 => {
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
            //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
            let mut revoked = DerReader::new(status_tlv.value);
            let when = revoked.read_tlv()?;
            revocation_time_unix = Some(time::parse_time(when.tag, when.value)?);
            if let Some(tag::CONTEXT_CONSTRUCTED_0) = revoked.peek_tag() {
                let mut wrapper = revoked.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
                let reason = wrapper.expect(TAG_ENUMERATED)?;
                wrapper.end()?;
                revocation_reason = reason.first().copied();
            }
            revoked.end()?;
            CertStatus::Revoked
        }
        got => {
            return Err(ParseError::UnexpectedTag {
                expected: 0x80,
                got,
            })
        }
    };
    let this = inner.read_tlv()?;
    let this_update_unix = time::parse_time(this.tag, this.value)?;
    let mut next_update_unix = None;
    if let Some(tag::CONTEXT_CONSTRUCTED_0) = inner.peek_tag() {
        let mut wrapper = inner.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
        let next = wrapper.read_tlv()?;
        wrapper.end()?;
        next_update_unix = Some(time::parse_time(next.tag, next.value)?);
    }
    // singleExtensions [1] EXPLICIT OPTIONAL: skipped.
    while !inner.is_empty() {
        let _ = inner.read_tlv()?;
    }
    Ok(SingleResponse {
        cert_id,
        status,
        this_update_unix,
        next_update_unix,
        revocation_time_unix,
        revocation_reason,
    })
}

/// The three values an OCSP request's CertID is built from: the leaf's
/// serial, the DER of the leaf's issuer name (hashed as issuerNameHash),
/// and the issuer's public key bits (hashed as issuerKeyHash). Fails if
/// `issuer_der` is not the certificate that issued `leaf_der`.
#[derive(Debug, Clone, Copy)]
pub struct CertIdInputs<'a> {
    pub serial_raw: &'a [u8],
    pub issuer_name_der: &'a [u8],
    pub issuer_key_bits: &'a [u8],
}

pub fn cert_id_inputs<'a>(
    leaf_der: &'a [u8],
    issuer_der: &'a [u8],
) -> Result<Option<CertIdInputs<'a>>, ParseError> {
    let leaf = Certificate::from_der(leaf_der)?;
    let issuer = Certificate::from_der(issuer_der)?;
    if leaf.issuer.raw != issuer.subject.raw {
        return Ok(None);
    }
    Ok(Some(CertIdInputs {
        serial_raw: leaf.serial_raw,
        issuer_name_der: leaf.issuer.raw,
        issuer_key_bits: issuer.spki.subject_public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            let len = content.len();
            let bytes: Vec<u8> = len
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

    fn generalized(text: &str) -> Vec<u8> {
        tlv(tag::TAG_GENERALIZED_TIME, text.as_bytes())
    }

    fn cert_id() -> Vec<u8> {
        let sha1 = tlv(tag::TAG_OBJECT_IDENTIFIER, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]);
        let mut alg = sha1;
        alg.extend_from_slice(&[0x05, 0x00]);
        let mut body = tlv(tag::TAG_SEQUENCE, &alg);
        body.extend(tlv(tag::TAG_OCTET_STRING, &[0xaa; 20]));
        body.extend(tlv(tag::TAG_OCTET_STRING, &[0xbb; 20]));
        body.extend(tlv(tag::TAG_INTEGER, &[0x01, 0x02, 0x03]));
        tlv(tag::TAG_SEQUENCE, &body)
    }

    fn single(status: &[u8], next_update: bool) -> Vec<u8> {
        let mut body = cert_id();
        body.extend_from_slice(status);
        body.extend(generalized("20260906120000Z"));
        if next_update {
            body.extend(tlv(0xa0, &generalized("20260913120000Z")));
        }
        tlv(tag::TAG_SEQUENCE, &body)
    }

    fn basic_response(singles: &[Vec<u8>], with_cert: bool) -> Vec<u8> {
        let mut data = tlv(0xa2, &tlv(tag::TAG_OCTET_STRING, &[0xcc; 20]));
        data.extend(generalized("20260906120100Z"));
        let mut list = Vec::new();
        for s in singles {
            list.extend_from_slice(s);
        }
        data.extend(tlv(tag::TAG_SEQUENCE, &list));
        let tbs = tlv(tag::TAG_SEQUENCE, &data);
        let mut basic = tbs.clone();
        // sha256WithRSAEncryption
        let mut alg = tlv(
            tag::TAG_OBJECT_IDENTIFIER,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
        alg.extend_from_slice(&[0x05, 0x00]);
        basic.extend(tlv(tag::TAG_SEQUENCE, &alg));
        basic.extend(tlv(tag::TAG_BIT_STRING, &[0x00, 0xde, 0xad]));
        if with_cert {
            basic.extend(tlv(
                0xa0,
                &tlv(tag::TAG_SEQUENCE, &tlv(tag::TAG_SEQUENCE, b"fake")),
            ));
        }
        let basic_seq = tlv(tag::TAG_SEQUENCE, &basic);
        let mut rb = tlv(tag::TAG_OBJECT_IDENTIFIER, OID_OCSP_BASIC);
        rb.extend(tlv(tag::TAG_OCTET_STRING, &basic_seq));
        let mut outer = tlv(TAG_ENUMERATED, &[0]);
        outer.extend(tlv(0xa0, &tlv(tag::TAG_SEQUENCE, &rb)));
        tlv(tag::TAG_SEQUENCE, &outer)
    }

    #[test]
    fn good_response_round_trips() {
        let der = basic_response(&[single(&[0x80, 0x00], true)], true);
        let parsed = OcspResponse::from_der(&der).unwrap();
        assert_eq!(parsed.status, ResponseStatus::Successful);
        assert!(matches!(parsed.responder_id, Some(ResponderId::ByKey(k)) if k == [0xcc; 20]));
        assert_eq!(parsed.produced_at_unix, Some(1_788_696_060));
        assert_eq!(parsed.signature, Some(&[0xde, 0xad][..]));
        assert_eq!(parsed.certs.len(), 1);
        let one = &parsed.responses[0];
        assert_eq!(one.status, CertStatus::Good);
        assert_eq!(one.cert_id.serial_raw, &[1, 2, 3]);
        assert_eq!(one.cert_id.issuer_key_hash, &[0xbb; 20]);
        assert_eq!(one.this_update_unix, 1_788_696_000);
        assert_eq!(one.next_update_unix, Some(1_789_300_800));
        assert!(parsed.tbs_response_data.unwrap().starts_with(&[0x30]));
    }

    #[test]
    fn revoked_response_carries_time_and_reason() {
        let mut revoked = generalized("20260901000000Z");
        revoked.extend(tlv(0xa0, &tlv(TAG_ENUMERATED, &[1])));
        let der = basic_response(&[single(&tlv(0xa1, &revoked), false)], false);
        let parsed = OcspResponse::from_der(&der).unwrap();
        let one = &parsed.responses[0];
        assert_eq!(one.status, CertStatus::Revoked);
        assert_eq!(one.revocation_time_unix, Some(1_788_220_800));
        assert_eq!(one.revocation_reason, Some(1));
        assert_eq!(crl_reason_name(1), "key_compromise");
        assert_eq!(one.next_update_unix, None);
    }

    #[test]
    fn unknown_status_and_error_statuses() {
        let der = basic_response(&[single(&[0x82, 0x00], false)], false);
        assert_eq!(
            OcspResponse::from_der(&der).unwrap().responses[0].status,
            CertStatus::Unknown
        );
        let try_later = tlv(tag::TAG_SEQUENCE, &tlv(TAG_ENUMERATED, &[3]));
        let parsed = OcspResponse::from_der(&try_later).unwrap();
        assert_eq!(parsed.status, ResponseStatus::TryLater);
        assert!(parsed.responses.is_empty());
        assert_eq!(ResponseStatus::Other(9).as_str(), "status_9");
    }

    #[test]
    fn malformed_input_errors_instead_of_panicking() {
        assert!(OcspResponse::from_der(&[0x30]).is_err());
        assert!(OcspResponse::from_der(&[0x30, 0x03, 0x0a, 0x01]).is_err());
        let bad_status = basic_response(&[single(&[0x83, 0x00], false)], false);
        assert!(OcspResponse::from_der(&bad_status).is_err());
    }
}
