// rust_certinfo/src/x509/extensions.rs
//
// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
// Extension  ::= SEQUENCE {
//     extnID    OBJECT IDENTIFIER,
//     critical  BOOLEAN DEFAULT FALSE,
//     extnValue OCTET STRING       -- contains DER-encoded extension type
// }
//
// We only parse three extensions today: BasicConstraints, SKI, AKI.
// Adding a new extension is a single accessor on `Extensions` plus a
// matching parser function — no changes to the parent walker required.

use crate::der::{oid, tag, DerReader, Oid};
use crate::error::ParseError;

#[derive(Debug, Clone, Copy)]
pub struct Extensions<'a> {
    body: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Extension<'a> {
    pub oid: Oid<'a>,
    /// `true` if the extension was marked critical. Not surfaced to Python
    /// today, but available to in-tree future extension parsers.
    #[allow(dead_code)]
    pub critical: bool,
    /// Inner DER bytes after unwrapping the OCTET STRING.
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthorityKeyIdentifier<'a> {
    pub key_identifier: Option<&'a [u8]>,
}

impl<'a> Extensions<'a> {
    /// Build an Extensions wrapper from the contents of a SEQUENCE OF
    /// Extension, i.e. the value bytes of the outer SEQUENCE.
    pub fn from_body(body: &'a [u8]) -> Self {
        Self { body }
    }

    /// Iterate all extensions in document order.
    pub fn iter(&self) -> ExtensionIter<'a> {
        ExtensionIter {
            reader: DerReader::new(self.body),
        }
    }

    /// Find a single extension by raw OID bytes. Returns the first match.
    fn find(&self, oid_bytes: &[u8]) -> Result<Option<Extension<'a>>, ParseError> {
        for ext in self.iter() {
            let ext = ext?;
            if ext.oid.as_bytes() == oid_bytes {
                return Ok(Some(ext));
            }
        }
        Ok(None)
    }

    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>, ParseError> {
        let Some(ext) = self.find(oid::OID_EXT_BASIC_CONSTRAINTS)? else {
            return Ok(None);
        };
        Ok(Some(parse_basic_constraints(ext.value)?))
    }

    pub fn subject_key_identifier(&self) -> Result<Option<&'a [u8]>, ParseError> {
        let Some(ext) = self.find(oid::OID_EXT_SKI)? else {
            return Ok(None);
        };
        // SubjectKeyIdentifier ::= KeyIdentifier
        // KeyIdentifier         ::= OCTET STRING
        let mut r = DerReader::new(ext.value);
        let value = r.expect(tag::TAG_OCTET_STRING)?;
        r.end()?;
        Ok(Some(value))
    }

    pub fn authority_key_identifier(
        &self,
    ) -> Result<Option<AuthorityKeyIdentifier<'a>>, ParseError> {
        let Some(ext) = self.find(oid::OID_EXT_AKI)? else {
            return Ok(None);
        };
        Ok(Some(parse_authority_key_identifier(ext.value)?))
    }
}

pub struct ExtensionIter<'a> {
    reader: DerReader<'a>,
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Result<Extension<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.peek_tag()?;
        let mut inner = match self.reader.expect_constructed(tag::TAG_SEQUENCE) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        let oid_value = match inner.expect(tag::TAG_OBJECT_IDENTIFIER) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let oid = match Oid::from_bytes(oid_value) {
            Ok(o) => o,
            Err(e) => return Some(Err(e)),
        };

        // critical BOOLEAN DEFAULT FALSE — present iff the next tag is
        // 0x01 (BOOLEAN), otherwise absent and the default applies.
        let critical = match inner.peek_tag() {
            Some(tag::TAG_BOOLEAN) => {
                let value = match inner.expect(tag::TAG_BOOLEAN) {
                    Ok(v) => v,
                    Err(e) => return Some(Err(e)),
                };
                value.first().copied().unwrap_or(0) != 0
            }
            _ => false,
        };
        let value = match inner.expect(tag::TAG_OCTET_STRING) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        if let Err(e) = inner.end() {
            return Some(Err(e));
        }
        Some(Ok(Extension {
            oid,
            critical,
            value,
        }))
    }
}

fn parse_basic_constraints(value: &[u8]) -> Result<BasicConstraints, ParseError> {
    // BasicConstraints ::= SEQUENCE {
    //     cA              BOOLEAN DEFAULT FALSE,
    //     pathLenConstraint INTEGER (0..MAX) OPTIONAL
    // }
    let mut r = DerReader::new(value);
    let mut inner = r.expect_constructed(tag::TAG_SEQUENCE)?;
    let mut bc = BasicConstraints {
        ca: false,
        path_len: None,
    };
    if let Some(tag::TAG_BOOLEAN) = inner.peek_tag() {
        let val = inner.expect(tag::TAG_BOOLEAN)?;
        bc.ca = val.first().copied().unwrap_or(0) != 0;
    }
    if let Some(tag::TAG_INTEGER) = inner.peek_tag() {
        let val = inner.expect(tag::TAG_INTEGER)?;
        // Decode small unsigned integer; cert path length is always small.
        let n = val
            .iter()
            .try_fold(0u64, |acc, &b| {
                acc.checked_shl(8).and_then(|v| v.checked_add(b as u64))
            })
            .ok_or(ParseError::IntegerOverflow)?;
        bc.path_len = Some(n.try_into().map_err(|_| ParseError::IntegerOverflow)?);
    }
    inner.end()?;
    r.end()?;
    Ok(bc)
}

fn parse_authority_key_identifier(value: &[u8]) -> Result<AuthorityKeyIdentifier<'_>, ParseError> {
    // AuthorityKeyIdentifier ::= SEQUENCE {
    //     keyIdentifier             [0] OCTET STRING OPTIONAL,
    //     authorityCertIssuer       [1] GeneralNames OPTIONAL,
    //     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    // }
    //
    // We only care about [0] (the key identifier). The IMPLICIT tagging
    // means the wire form is `0x80 || length || octet_string_bytes`.
    let mut r = DerReader::new(value);
    let mut inner = r.expect_constructed(tag::TAG_SEQUENCE)?;
    let mut key_identifier = None;
    while inner.peek_tag().is_some() {
        let tlv = inner.read_tlv()?;
        if tlv.tag == 0x80 {
            // [0] IMPLICIT OCTET STRING — value is the raw key identifier.
            key_identifier = Some(tlv.value);
        }
        // [1] and [2] are skipped — we don't surface them today.
    }
    r.end()?;
    Ok(AuthorityKeyIdentifier { key_identifier })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_constraints_ca_true() {
        // BasicConstraints { cA TRUE } extension value (the OCTET STRING contents)
        // SEQUENCE { BOOLEAN TRUE } = 30 03 01 01 FF
        let value = [tag::TAG_SEQUENCE, 0x03, tag::TAG_BOOLEAN, 0x01, 0xff];
        let bc = parse_basic_constraints(&value).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len, None);
    }

    #[test]
    fn basic_constraints_default_false() {
        // SEQUENCE {} = 30 00
        let value = [tag::TAG_SEQUENCE, 0x00];
        let bc = parse_basic_constraints(&value).unwrap();
        assert!(!bc.ca);
        assert_eq!(bc.path_len, None);
    }

    #[test]
    fn basic_constraints_with_path_len() {
        // SEQUENCE { BOOLEAN TRUE, INTEGER 3 }
        let value = [
            tag::TAG_SEQUENCE,
            0x06,
            tag::TAG_BOOLEAN,
            0x01,
            0xff,
            tag::TAG_INTEGER,
            0x01,
            0x03,
        ];
        let bc = parse_basic_constraints(&value).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len, Some(3));
    }

    #[test]
    fn aki_key_identifier_only() {
        // SEQUENCE { [0] IMPLICIT OCTET STRING (20 bytes) }
        let mut value = vec![tag::TAG_SEQUENCE, 0x16, 0x80, 0x14];
        value.extend(vec![0xab; 20]);
        let aki = parse_authority_key_identifier(&value).unwrap();
        assert_eq!(aki.key_identifier.unwrap().len(), 20);
        assert!(aki.key_identifier.unwrap().iter().all(|&b| b == 0xab));
    }

    #[test]
    fn aki_with_extra_fields_ignored() {
        // SEQUENCE { [0] OCTET STRING (4 bytes), [1] (2 bytes) }
        let value = [
            tag::TAG_SEQUENCE,
            0x0a,
            0x80,
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
            0xa1,
            0x02,
            0xff,
            0xff,
        ];
        let aki = parse_authority_key_identifier(&value).unwrap();
        assert_eq!(aki.key_identifier, Some(&[0x01, 0x02, 0x03, 0x04][..]));
    }
}
