// rust_certinfo/src/x509/extensions.rs
//
// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
// Extension  ::= SEQUENCE {
//     extnID    OBJECT IDENTIFIER,
//     critical  BOOLEAN DEFAULT FALSE,
//     extnValue OCTET STRING       -- contains DER-encoded extension type
// }
//
// Parsed today: BasicConstraints, SKI, AKI, KeyUsage, ExtendedKeyUsage.
// Adding a new extension is a single accessor on `Extensions` plus a
// matching parser function, no changes to the parent walker required.

use crate::der::{oid, tag, DerReader, Oid};
use crate::error::ParseError;

/// id-ce-keyUsage (2.5.29.15)
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// id-ce-extKeyUsage (2.5.29.37)
const OID_EXT_EKU: &[u8] = &[0x55, 0x1d, 0x25];

#[derive(Debug, Clone, Copy)]
pub struct Extensions<'a> {
    body: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Extension<'a> {
    pub oid: Oid<'a>,
    /// `true` if the extension was marked critical. The CRL parser reports
    /// critical extensions it does not process (RFC 5280 §5.2).
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

/// The `KeyUsage` BIT STRING (RFC 5280 §4.2.1.3), bit 0 in the high bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    /// The nine defined bits, in bit order, as the snake_case names Python
    /// reports.
    pub const NAMES: [&'static str; 9] = [
        "digital_signature",
        "non_repudiation",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    ];

    /// Whether bit `index` (0 = digitalSignature) is set.
    pub fn has(&self, index: usize) -> bool {
        index < 16 && self.bits & (0x8000 >> index) != 0
    }

    /// `cRLSign` (bit 6), the one RFC 5280 §6.3.3 step (f) requires of a
    /// CRL issuer whose certificate carries this extension.
    pub fn crl_sign(&self) -> bool {
        self.has(6)
    }

    /// The names of the bits that are set, in bit order.
    pub fn names(&self) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .enumerate()
            .filter(|(index, _)| self.has(*index))
            .map(|(_, name)| *name)
            .collect()
    }
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
    pub(crate) fn find(&self, oid_bytes: &[u8]) -> Result<Option<Extension<'a>>, ParseError> {
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

    /// The OIDs of `ExtendedKeyUsage`, or an empty list when absent.
    pub fn extended_key_usage(&self) -> Result<Vec<Oid<'a>>, ParseError> {
        let Some(ext) = self.find(OID_EXT_EKU)? else {
            return Ok(Vec::new());
        };
        let mut top = DerReader::new(ext.value);
        let mut seq = top.expect_constructed(tag::TAG_SEQUENCE)?;
        top.end()?;
        let mut purposes = Vec::new();
        while !seq.is_empty() {
            purposes.push(Oid::from_bytes(seq.expect(tag::TAG_OBJECT_IDENTIFIER)?)?);
        }
        Ok(purposes)
    }

    /// The `KeyUsage` bits, or `None` when the extension is absent.
    pub fn key_usage(&self) -> Result<Option<KeyUsage>, ParseError> {
        let Some(ext) = self.find(OID_EXT_KEY_USAGE)? else {
            return Ok(None);
        };
        Ok(Some(parse_key_usage(ext.value)?))
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

        // critical BOOLEAN DEFAULT FALSE, present iff the next tag is
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
        // A leading 0x00 is a sign byte unless it is the whole value, i.e. 0.
        let (had_sign_byte, digits) = match val {
            [0x00, rest @ ..] if !rest.is_empty() => (true, rest),
            _ => (false, val),
        };
        if digits.is_empty() || digits.len() > 8 {
            return Err(ParseError::IntegerOverflow);
        }
        if !had_sign_byte && digits[0] & 0x80 != 0 {
            return Err(ParseError::IntegerOverflow);
        }
        if had_sign_byte && digits[0] == 0x00 {
            // Two leading zero octets: DER (X.690 §8.3.2) allows the sign
            // byte only when the next octet's high bit is set, so this is a
            // padded re-encoding of a smaller value.
            return Err(ParseError::IntegerOverflow);
        }
        let n = digits
            .iter()
            .try_fold(0u64, |acc, &b| {
                acc.checked_mul(256)
                    .and_then(|v| v.checked_add(u64::from(b)))
            })
            .ok_or(ParseError::IntegerOverflow)?;
        bc.path_len = Some(n.try_into().map_err(|_| ParseError::IntegerOverflow)?);
    }
    inner.end()?;
    r.end()?;
    Ok(bc)
}

fn parse_key_usage(value: &[u8]) -> Result<KeyUsage, ParseError> {
    // KeyUsage ::= BIT STRING, at most nine bits. The first content octet
    // counts the unused low bits of the last one; DER drops trailing zero
    // octets, so a certificate with no bits set encodes as `03 01 00`.
    let mut r = DerReader::new(value);
    let content = r.expect(tag::TAG_BIT_STRING)?;
    r.end()?;
    let Some((&unused, bytes)) = content.split_first() else {
        return Err(ParseError::InvalidBitString);
    };
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(ParseError::InvalidBitString);
    }
    let mut bits = 0u16;
    if let Some(&first) = bytes.first() {
        bits |= u16::from(first) << 8;
    }
    if let Some(&second) = bytes.get(1) {
        bits |= u16::from(second);
    }
    // Clear the unused low bits of the last octet that landed in `bits`,
    // and everything past the ninth bit, which RFC 5280 does not define.
    let last_used_in_bits = match bytes.len() {
        0 => 0,
        1 => 8 - u32::from(unused),
        _ => 16 - u32::from(unused),
    };
    let keep = if last_used_in_bits == 0 {
        0
    } else {
        !0u16 << (16 - last_used_in_bits)
    };
    bits &= keep & 0xff80;
    Ok(KeyUsage { bits })
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
            // [0] IMPLICIT OCTET STRING, value is the raw key identifier.
            key_identifier = Some(tlv.value);
        }
        // [1] and [2] are skipped, we don't surface them today.
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
    fn basic_constraints_rejects_oversized_path_len() {
        // SEQUENCE { INTEGER 01 00 00 00 00 00 00 00 01 } (2^64 + 1): too
        // wide to fit the path length in a `u64`.
        let mut value = vec![tag::TAG_SEQUENCE, 0x0b, tag::TAG_INTEGER, 0x09, 0x01];
        value.extend(vec![0x00u8; 7]);
        value.push(0x01);
        assert_eq!(
            parse_basic_constraints(&value).unwrap_err(),
            ParseError::IntegerOverflow
        );
    }

    #[test]
    fn basic_constraints_rejects_non_minimal_path_len() {
        // SEQUENCE { INTEGER 00 00 20 }: a second leading zero octet, which
        // X.690 §8.3.2 forbids because the first one alone already encodes 32.
        let value = [
            tag::TAG_SEQUENCE,
            0x05,
            tag::TAG_INTEGER,
            0x03,
            0x00,
            0x00,
            0x20,
        ];
        assert_eq!(
            parse_basic_constraints(&value).unwrap_err(),
            ParseError::IntegerOverflow
        );
        // SEQUENCE { INTEGER 00 80 }: the sign byte the same rule requires,
        // since 0x80's high bit would otherwise read as negative.
        let value = [tag::TAG_SEQUENCE, 0x04, tag::TAG_INTEGER, 0x02, 0x00, 0x80];
        assert_eq!(parse_basic_constraints(&value).unwrap().path_len, Some(128));
    }

    #[test]
    fn key_usage_bits_are_named_in_order() {
        // BIT STRING, 1 unused bit, 0000 011x: keyCertSign and cRLSign, the
        // usual CA key usage (`03 02 01 06`).
        let ku = parse_key_usage(&[tag::TAG_BIT_STRING, 0x02, 0x01, 0x06]).unwrap();
        assert!(ku.crl_sign());
        assert_eq!(ku.names(), vec!["key_cert_sign", "crl_sign"]);
        // 5 unused bits, 101x xxxx: digitalSignature and keyEncipherment.
        let ku = parse_key_usage(&[tag::TAG_BIT_STRING, 0x02, 0x05, 0xa0]).unwrap();
        assert!(!ku.crl_sign());
        assert_eq!(ku.names(), vec!["digital_signature", "key_encipherment"]);
        // Two content octets, 7 unused: decipherOnly is bit 8.
        let ku = parse_key_usage(&[tag::TAG_BIT_STRING, 0x03, 0x07, 0x00, 0x80]).unwrap();
        assert_eq!(ku.names(), vec!["decipher_only"]);
        // No bits at all.
        let ku = parse_key_usage(&[tag::TAG_BIT_STRING, 0x01, 0x00]).unwrap();
        assert!(ku.names().is_empty());
    }

    #[test]
    fn key_usage_ignores_unused_bits_and_rejects_bad_prefixes() {
        // 7 unused bits but the low seven are set: they do not count.
        let ku = parse_key_usage(&[tag::TAG_BIT_STRING, 0x02, 0x07, 0xff]).unwrap();
        assert_eq!(ku.names(), vec!["digital_signature"]);
        assert_eq!(
            parse_key_usage(&[tag::TAG_BIT_STRING, 0x02, 0x08, 0x80]).unwrap_err(),
            ParseError::InvalidBitString
        );
        assert_eq!(
            parse_key_usage(&[tag::TAG_BIT_STRING, 0x00]).unwrap_err(),
            ParseError::InvalidBitString
        );
        assert!(parse_key_usage(&[tag::TAG_OCTET_STRING, 0x01, 0x00]).is_err());
    }

    #[test]
    fn key_usage_is_none_when_absent() {
        assert_eq!(Extensions::from_body(&[]).key_usage().unwrap(), None);
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
