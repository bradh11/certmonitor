// rust_certinfo/src/x509/crl.rs
//
// CertificateList (RFC 5280 §5) for the revocation validator: the CRL's
// validity window for caching, and a lookup of one serial so a revoked
// verdict can carry the entry's time and reason. Signature verification
// is OpenSSL's job today (the CRL is loaded into a verifying TLS context)
// and moves in-tree with `crate::x509::verify`.
//
// CertificateList ::= SEQUENCE {
//     tbsCertList         TBSCertList,
//     signatureAlgorithm  AlgorithmIdentifier,
//     signatureValue      BIT STRING }
// TBSCertList ::= SEQUENCE {
//     version              INTEGER OPTIONAL,
//     signature            AlgorithmIdentifier,
//     issuer               Name,
//     thisUpdate           Time,
//     nextUpdate           Time OPTIONAL,
//     revokedCertificates  SEQUENCE OF SEQUENCE {
//         userCertificate     INTEGER,
//         revocationDate      Time,
//         crlEntryExtensions  Extensions OPTIONAL } OPTIONAL,
//     crlExtensions        [0] EXPLICIT Extensions OPTIONAL }

use crate::der::{tag, time, DerReader};
use crate::error::ParseError;
use crate::x509::extensions::Extensions;
use crate::x509::{algorithm::AlgorithmIdentifier, name::Name};

/// id-ce-cRLReasons (2.5.29.21)
const OID_CRL_REASON: &[u8] = &[0x55, 0x1d, 0x15];
/// id-ce-deltaCRLIndicator (2.5.29.27)
const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
/// id-ce-issuingDistributionPoint (2.5.29.28)
const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];

#[derive(Debug, Clone, Copy)]
pub struct CrlEntry {
    pub revocation_time_unix: i64,
    pub reason: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct Crl<'a> {
    pub issuer: Name<'a>,
    pub this_update_unix: i64,
    pub next_update_unix: Option<i64>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// Raw DER of tbsCertList, the bytes the issuer signed.
    pub tbs_cert_list: &'a [u8],
    /// Signature BIT STRING contents after the unused-bits byte.
    pub signature: &'a [u8],
    /// Value bytes of the revokedCertificates SEQUENCE (empty when absent).
    revoked_body: &'a [u8],
    extensions: Extensions<'a>,
}

/// The scope narrowing an issuing distribution point declares (RFC 5280 §5.2.5).
/// Every flag defaults to false when the extension omits it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IssuingDistributionPoint {
    pub only_contains_user_certs: bool,
    pub only_contains_ca_certs: bool,
    pub only_some_reasons: bool,
    pub indirect_crl: bool,
    pub only_contains_attribute_certs: bool,
}

impl<'a> Crl<'a> {
    pub fn from_der(der: &'a [u8]) -> Result<Self, ParseError> {
        let mut top = DerReader::new(der);
        let mut outer = top.expect_constructed(tag::TAG_SEQUENCE)?;
        top.end()?;
        let tbs_tlv = outer.read_tlv()?;
        if tbs_tlv.tag != tag::TAG_SEQUENCE {
            return Err(ParseError::UnexpectedTag {
                expected: tag::TAG_SEQUENCE,
                got: tbs_tlv.tag,
            });
        }
        let signature_algorithm = AlgorithmIdentifier::parse(&mut outer)?;
        let bits = outer.expect(tag::TAG_BIT_STRING)?;
        let signature = match bits.split_first() {
            Some((0, rest)) => rest,
            _ => return Err(ParseError::InvalidBitString),
        };
        outer.end()?;

        let mut tbs = DerReader::new(tbs_tlv.value);
        if let Some(tag::TAG_INTEGER) = tbs.peek_tag() {
            let _version = tbs.read_tlv()?;
        }
        let _inner_algorithm = AlgorithmIdentifier::parse(&mut tbs)?;
        let issuer = Name::parse(&mut tbs)?;
        let this = tbs.read_tlv()?;
        let this_update_unix = time::parse_time(this.tag, this.value)?;
        let mut next_update_unix = None;
        let mut revoked_body: &'a [u8] = &[];
        let mut extensions_body: &'a [u8] = &[];
        while !tbs.is_empty() {
            match tbs.peek_tag() {
                Some(tag::TAG_UTC_TIME) | Some(tag::TAG_GENERALIZED_TIME) => {
                    let item = tbs.read_tlv()?;
                    next_update_unix = Some(time::parse_time(item.tag, item.value)?);
                }
                Some(tag::TAG_SEQUENCE) => {
                    revoked_body = tbs.read_tlv()?.value;
                }
                Some(tag::CONTEXT_CONSTRUCTED_0) => {
                    let mut wrapper = tbs.expect_constructed(tag::CONTEXT_CONSTRUCTED_0)?;
                    extensions_body = wrapper.expect(tag::TAG_SEQUENCE)?;
                    wrapper.end()?;
                }
                _ => {
                    let _ = tbs.read_tlv()?;
                }
            }
        }
        Ok(Crl {
            issuer,
            this_update_unix,
            next_update_unix,
            signature_algorithm,
            tbs_cert_list: tbs_tlv.raw,
            signature,
            revoked_body,
            extensions: Extensions::from_body(extensions_body),
        })
    }

    /// Number of revoked certificates listed.
    pub fn revoked_count(&self) -> Result<usize, ParseError> {
        let mut reader = DerReader::new(self.revoked_body);
        let mut count = 0;
        while !reader.is_empty() {
            let _ = reader.read_tlv()?;
            count += 1;
        }
        Ok(count)
    }

    /// Find the entry for `serial_raw` (INTEGER value bytes), if listed.
    /// Leading zero bytes are ignored on both sides, so a serial rendered
    /// from hex matches its DER form.
    pub fn lookup(&self, serial_raw: &[u8]) -> Result<Option<CrlEntry>, ParseError> {
        let wanted = strip_leading_zeros(serial_raw);
        let mut reader = DerReader::new(self.revoked_body);
        while !reader.is_empty() {
            let mut entry = reader.expect_constructed(tag::TAG_SEQUENCE)?;
            let serial = entry.expect(tag::TAG_INTEGER)?;
            if strip_leading_zeros(serial) != wanted {
                continue;
            }
            let when = entry.read_tlv()?;
            let revocation_time_unix = time::parse_time(when.tag, when.value)?;
            let mut reason = None;
            if !entry.is_empty() {
                let mut extensions = entry.expect_constructed(tag::TAG_SEQUENCE)?;
                while !extensions.is_empty() {
                    let mut ext = extensions.expect_constructed(tag::TAG_SEQUENCE)?;
                    let oid = ext.expect(tag::TAG_OBJECT_IDENTIFIER)?;
                    if let Some(tag::TAG_BOOLEAN) = ext.peek_tag() {
                        let _critical = ext.read_tlv()?;
                    }
                    let value = ext.expect(tag::TAG_OCTET_STRING)?;
                    if oid == OID_CRL_REASON {
                        let mut inner = DerReader::new(value);
                        let code = inner.expect(0x0a)?;
                        reason = code.first().copied();
                    }
                }
            }
            return Ok(Some(CrlEntry {
                revocation_time_unix,
                reason,
            }));
        }
        Ok(None)
    }

    /// Whether the CRL carries the delta CRL indicator, meaning it lists only
    /// changes since a base CRL and cannot answer for a serial it omits.
    pub fn is_delta(&self) -> Result<bool, ParseError> {
        Ok(self.extensions.find(OID_DELTA_CRL_INDICATOR)?.is_some())
    }

    /// The issuing distribution point's scope flags, if the extension is present.
    ///
    /// IssuingDistributionPoint ::= SEQUENCE {
    ///     distributionPoint          [0] DistributionPointName OPTIONAL,
    ///     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    ///     onlySomeReasons            [3] ReasonFlags OPTIONAL,
    ///     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    ///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
    pub fn issuing_distribution_point(
        &self,
    ) -> Result<Option<IssuingDistributionPoint>, ParseError> {
        let Some(ext) = self.extensions.find(OID_ISSUING_DISTRIBUTION_POINT)? else {
            return Ok(None);
        };
        let mut outer = DerReader::new(ext.value);
        let mut seq = outer.expect_constructed(tag::TAG_SEQUENCE)?;
        outer.end()?;
        let mut idp = IssuingDistributionPoint::default();
        while !seq.is_empty() {
            let item = seq.read_tlv()?;
            let flag = item.value.first().is_some_and(|b| *b != 0);
            match item.tag {
                0x81 => idp.only_contains_user_certs = flag,
                0x82 => idp.only_contains_ca_certs = flag,
                0x83 => idp.only_some_reasons = true,
                0x84 => idp.indirect_crl = flag,
                0x85 => idp.only_contains_attribute_certs = flag,
                _ => {} // [0] distributionPoint and anything unknown
            }
        }
        Ok(Some(idp))
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
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

    fn utc(text: &str) -> Vec<u8> {
        tlv(tag::TAG_UTC_TIME, text.as_bytes())
    }

    fn crl(entries: &[Vec<u8>], next_update: bool) -> Vec<u8> {
        let mut alg = tlv(
            tag::TAG_OBJECT_IDENTIFIER,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
        alg.extend_from_slice(&[0x05, 0x00]);
        let alg = tlv(tag::TAG_SEQUENCE, &alg);
        let mut tbs = tlv(tag::TAG_INTEGER, &[1]);
        tbs.extend_from_slice(&alg);
        tbs.extend(tlv(tag::TAG_SEQUENCE, &[])); // empty issuer Name
        tbs.extend(utc("260906120000Z"));
        if next_update {
            tbs.extend(utc("260913120000Z"));
        }
        if !entries.is_empty() {
            let mut list = Vec::new();
            for e in entries {
                list.extend_from_slice(e);
            }
            tbs.extend(tlv(tag::TAG_SEQUENCE, &list));
        }
        let mut outer = tlv(tag::TAG_SEQUENCE, &tbs);
        outer.extend_from_slice(&alg);
        outer.extend(tlv(tag::TAG_BIT_STRING, &[0x00, 0x01, 0x02]));
        tlv(tag::TAG_SEQUENCE, &outer)
    }

    fn entry(serial: &[u8], reason: Option<u8>) -> Vec<u8> {
        let mut body = tlv(tag::TAG_INTEGER, serial);
        body.extend(utc("260901000000Z"));
        if let Some(code) = reason {
            let mut ext = tlv(tag::TAG_OBJECT_IDENTIFIER, OID_CRL_REASON);
            ext.extend(tlv(tag::TAG_OCTET_STRING, &tlv(0x0a, &[code])));
            body.extend(tlv(tag::TAG_SEQUENCE, &tlv(tag::TAG_SEQUENCE, &ext)));
        }
        tlv(tag::TAG_SEQUENCE, &body)
    }

    #[test]
    fn validity_and_lookup() {
        let der = crl(&[entry(&[0x10], None), entry(&[0x20], Some(4))], true);
        let parsed = Crl::from_der(&der).unwrap();
        assert_eq!(parsed.this_update_unix, 1_788_696_000);
        assert_eq!(parsed.next_update_unix, Some(1_789_300_800));
        assert_eq!(parsed.revoked_count().unwrap(), 2);
        assert_eq!(parsed.signature, &[1, 2]);
        assert!(parsed.lookup(&[0x30]).unwrap().is_none());
        let hit = parsed.lookup(&[0x20]).unwrap().unwrap();
        assert_eq!(hit.revocation_time_unix, 1_788_220_800);
        assert_eq!(hit.reason, Some(4));
        assert_eq!(parsed.lookup(&[0x10]).unwrap().unwrap().reason, None);
        assert!(parsed.lookup(&[0x00, 0x20]).unwrap().is_some());
    }

    #[test]
    fn empty_crl_without_next_update() {
        let der = crl(&[], false);
        let parsed = Crl::from_der(&der).unwrap();
        assert_eq!(parsed.next_update_unix, None);
        assert_eq!(parsed.revoked_count().unwrap(), 0);
        assert!(parsed.lookup(&[1]).unwrap().is_none());
    }

    #[test]
    fn malformed_input_errors_instead_of_panicking() {
        assert!(Crl::from_der(&[0x30, 0x00]).is_err());
        assert!(Crl::from_der(&[0x04, 0x01, 0x00]).is_err());
    }

    fn ext(oid: &[u8], value: &[u8]) -> Vec<u8> {
        let mut body = tlv(tag::TAG_OBJECT_IDENTIFIER, oid);
        body.extend(tlv(tag::TAG_OCTET_STRING, value));
        tlv(tag::TAG_SEQUENCE, &body)
    }

    fn crl_with_extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut alg = tlv(
            tag::TAG_OBJECT_IDENTIFIER,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
        alg.extend_from_slice(&[0x05, 0x00]);
        let alg = tlv(tag::TAG_SEQUENCE, &alg);
        let mut tbs = tlv(tag::TAG_INTEGER, &[1]);
        tbs.extend_from_slice(&alg);
        tbs.extend(tlv(tag::TAG_SEQUENCE, &[])); // empty issuer Name
        tbs.extend(utc("260906120000Z"));
        if !extensions.is_empty() {
            let mut list = Vec::new();
            for e in extensions {
                list.extend_from_slice(e);
            }
            let seq = tlv(tag::TAG_SEQUENCE, &list);
            tbs.extend(tlv(tag::CONTEXT_CONSTRUCTED_0, &seq));
        }
        let mut outer = tlv(tag::TAG_SEQUENCE, &tbs);
        outer.extend_from_slice(&alg);
        outer.extend(tlv(tag::TAG_BIT_STRING, &[0x00, 0x01, 0x02]));
        tlv(tag::TAG_SEQUENCE, &outer)
    }

    #[test]
    fn no_extensions_means_no_scope_narrowing() {
        let der = crl_with_extensions(&[]);
        let parsed = Crl::from_der(&der).unwrap();
        assert!(!parsed.is_delta().unwrap());
        assert!(parsed.issuing_distribution_point().unwrap().is_none());
    }

    #[test]
    fn delta_crl_indicator_is_reported() {
        let der =
            crl_with_extensions(&[ext(OID_DELTA_CRL_INDICATOR, &tlv(tag::TAG_INTEGER, &[5]))]);
        let parsed = Crl::from_der(&der).unwrap();
        assert!(parsed.is_delta().unwrap());
    }

    #[test]
    fn issuing_distribution_point_scope_flags() {
        let idp_body = {
            let mut body = tlv(0x83, &[0x03, 0x02, 0x05, 0x20]);
            body.extend(tlv(0x84, &[0xff]));
            body
        };
        let der = crl_with_extensions(&[ext(
            OID_ISSUING_DISTRIBUTION_POINT,
            &tlv(tag::TAG_SEQUENCE, &idp_body),
        )]);
        let parsed = Crl::from_der(&der).unwrap();
        let idp = parsed.issuing_distribution_point().unwrap().unwrap();
        assert!(!idp.only_contains_user_certs);
        assert!(!idp.only_contains_ca_certs);
        assert!(idp.only_some_reasons);
        assert!(idp.indirect_crl);
        assert!(!idp.only_contains_attribute_certs);
    }
}
