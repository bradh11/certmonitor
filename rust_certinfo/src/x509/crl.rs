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
use crate::x509::{algorithm::AlgorithmIdentifier, name::Name};

/// id-ce-cRLReasons (2.5.29.21)
const OID_CRL_REASON: &[u8] = &[0x55, 0x1d, 0x15];

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
        while !tbs.is_empty() {
            let item = tbs.read_tlv()?;
            match item.tag {
                tag::TAG_UTC_TIME | tag::TAG_GENERALIZED_TIME => {
                    next_update_unix = Some(time::parse_time(item.tag, item.value)?);
                }
                tag::TAG_SEQUENCE => revoked_body = item.value,
                _ => {} // crlExtensions [0] and anything trailing
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
}
