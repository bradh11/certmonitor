// rust_certinfo/src/x509/name.rs
//
// Name ::= CHOICE { rdnSequence RDNSequence }
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
//
// `Name` keeps the raw outer SEQUENCE bytes for byte-equality comparison
// (which is what we use to verify chain-link parent.subject == child.issuer).
// The attribute accessors (`common_name`, `organization`, etc.) walk the
// nested SEQUENCE/SET/SEQUENCE structure on demand.

use crate::der::{string, tag, DerReader, Oid};
use crate::error::ParseError;

#[derive(Debug, Clone, Copy)]
pub struct Name<'a> {
    /// Outer Name TLV including the SEQUENCE tag and length prefix. Used by
    /// `chain_analysis` for canonical DN equality comparison.
    pub raw: &'a [u8],
    body: &'a [u8],
}

impl<'a> Name<'a> {
    /// Parse a Name from a sub-reader positioned at its outer SEQUENCE tag.
    /// Advances the reader past the entire Name.
    pub fn parse(reader: &mut DerReader<'a>) -> Result<Self, ParseError> {
        let tlv = reader.read_tlv()?;
        if tlv.tag != tag::TAG_SEQUENCE {
            return Err(ParseError::UnexpectedTag {
                expected: tag::TAG_SEQUENCE,
                got: tlv.tag,
            });
        }
        Ok(Self {
            raw: tlv.raw,
            body: tlv.value,
        })
    }

    pub fn common_name(&self) -> Option<String> {
        self.first_value_of(crate::der::oid::OID_AT_COMMON_NAME)
    }

    pub fn organization(&self) -> Option<String> {
        self.first_value_of(crate::der::oid::OID_AT_ORGANIZATION_NAME)
    }

    pub fn organizational_unit(&self) -> Option<String> {
        self.first_value_of(crate::der::oid::OID_AT_ORGANIZATIONAL_UNIT_NAME)
    }

    pub fn country(&self) -> Option<String> {
        self.first_value_of(crate::der::oid::OID_AT_COUNTRY_NAME)
    }

    /// Return the first AttributeTypeAndValue whose type matches `attr_oid_bytes`.
    /// Stops at the first match, mirroring `x509-parser`'s `iter_*().next()` calls.
    fn first_value_of(&self, attr_oid_bytes: &[u8]) -> Option<String> {
        let mut rdns = DerReader::new(self.body);
        while rdns.peek_tag().is_some() {
            let rdn_inner = rdns.expect_constructed(tag::TAG_SET).ok()?;
            // Walk every ATV in the RDN set
            let mut atvs = rdn_inner;
            while atvs.peek_tag().is_some() {
                let mut atv = atvs.expect_constructed(tag::TAG_SEQUENCE).ok()?;
                let oid_bytes = atv.expect(tag::TAG_OBJECT_IDENTIFIER).ok()?;
                if oid_bytes == attr_oid_bytes {
                    let value_tlv = atv.read_tlv().ok()?;
                    return string::parse_string(value_tlv.tag, value_tlv.value).ok();
                }
            }
        }
        None
    }

    /// Iterate every (type OID, decoded value) pair in document order.
    /// Used by future extension code that needs more than the four
    /// well-known fields above.
    #[allow(dead_code)]
    pub fn iter_attributes(&self) -> NameAttrIter<'a> {
        NameAttrIter {
            rdns: DerReader::new(self.body),
            current_rdn: None,
        }
    }
}

#[allow(dead_code)]
pub struct NameAttrIter<'a> {
    rdns: DerReader<'a>,
    current_rdn: Option<DerReader<'a>>,
}

impl<'a> Iterator for NameAttrIter<'a> {
    type Item = Result<(Oid<'a>, String), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If we're inside an RDN, try to read the next ATV.
            if let Some(rdn) = self.current_rdn.as_mut() {
                if rdn.peek_tag().is_some() {
                    let mut atv = match rdn.expect_constructed(tag::TAG_SEQUENCE) {
                        Ok(r) => r,
                        Err(e) => return Some(Err(e)),
                    };
                    let oid_value = match atv.expect(tag::TAG_OBJECT_IDENTIFIER) {
                        Ok(v) => v,
                        Err(e) => return Some(Err(e)),
                    };
                    let oid = match Oid::from_bytes(oid_value) {
                        Ok(o) => o,
                        Err(e) => return Some(Err(e)),
                    };
                    let value_tlv = match atv.read_tlv() {
                        Ok(t) => t,
                        Err(e) => return Some(Err(e)),
                    };
                    let value = match string::parse_string(value_tlv.tag, value_tlv.value) {
                        Ok(s) => s,
                        Err(e) => return Some(Err(e)),
                    };
                    return Some(Ok((oid, value)));
                }
                self.current_rdn = None;
            }
            // Need to advance to the next RDN.
            self.rdns.peek_tag()?;
            let next_rdn = match self.rdns.expect_constructed(tag::TAG_SET) {
                Ok(r) => r,
                Err(e) => return Some(Err(e)),
            };
            self.current_rdn = Some(next_rdn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Name DER for `CN=example.com, O=Example Inc, C=US`.
    fn sample_name_der() -> Vec<u8> {
        // The DER for this is hand-built byte-by-byte to keep the test
        // self-contained.
        // RDN 1: SET { SEQUENCE { OID 2.5.4.6 (countryName), PrintableString "US" } }
        let rdn_c = vec![
            tag::TAG_SET,
            0x0b,
            tag::TAG_SEQUENCE,
            0x09,
            tag::TAG_OBJECT_IDENTIFIER,
            0x03,
            0x55,
            0x04,
            0x06,
            tag::TAG_PRINTABLE_STRING,
            0x02,
            b'U',
            b'S',
        ];
        // RDN 2: SET { SEQUENCE { OID 2.5.4.10 (organizationName), UTF8String "Example Inc" } }
        let rdn_o = vec![
            tag::TAG_SET,
            0x14,
            tag::TAG_SEQUENCE,
            0x12,
            tag::TAG_OBJECT_IDENTIFIER,
            0x03,
            0x55,
            0x04,
            0x0a,
            tag::TAG_UTF8_STRING,
            0x0b,
            b'E',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b' ',
            b'I',
            b'n',
            b'c',
        ];
        // RDN 3: SET { SEQUENCE { OID 2.5.4.3 (commonName), UTF8String "example.com" } }
        let rdn_cn = vec![
            tag::TAG_SET,
            0x14,
            tag::TAG_SEQUENCE,
            0x12,
            tag::TAG_OBJECT_IDENTIFIER,
            0x03,
            0x55,
            0x04,
            0x03,
            tag::TAG_UTF8_STRING,
            0x0b,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
        ];

        let mut body: Vec<u8> = Vec::new();
        body.extend(&rdn_c);
        body.extend(&rdn_o);
        body.extend(&rdn_cn);

        let mut out = vec![tag::TAG_SEQUENCE, body.len() as u8];
        out.extend(body);
        out
    }

    #[test]
    fn parses_attributes() {
        let bytes = sample_name_der();
        let mut r = DerReader::new(&bytes);
        let name = Name::parse(&mut r).unwrap();
        assert_eq!(name.common_name().as_deref(), Some("example.com"));
        assert_eq!(name.organization().as_deref(), Some("Example Inc"));
        assert_eq!(name.country().as_deref(), Some("US"));
        assert_eq!(name.organizational_unit(), None);
    }

    #[test]
    fn raw_includes_outer_sequence() {
        let bytes = sample_name_der();
        let mut r = DerReader::new(&bytes);
        let name = Name::parse(&mut r).unwrap();
        assert_eq!(name.raw, bytes.as_slice());
    }

    #[test]
    fn iter_attributes_visits_all() {
        let bytes = sample_name_der();
        let mut r = DerReader::new(&bytes);
        let name = Name::parse(&mut r).unwrap();
        let attrs: Vec<(String, String)> = name
            .iter_attributes()
            .filter_map(Result::ok)
            .map(|(oid, val)| (oid.to_id_string(), val))
            .collect();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0], ("2.5.4.6".to_string(), "US".to_string()));
    }
}
