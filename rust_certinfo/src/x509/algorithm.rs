// rust_certinfo/src/x509/algorithm.rs
//
// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm   OBJECT IDENTIFIER,
//     parameters  ANY DEFINED BY algorithm OPTIONAL
// }
//
// We expose `parameters` as the raw TLV slice (tag + length + value) so the
// caller can re-parse it for whatever type the algorithm uses. For EC keys
// the parameters are an ECParameters CHOICE which in practice is always a
// named-curve OID — `x509::spki` re-parses that OID itself.

use crate::der::{tag, DerReader, Oid, Tlv};
use crate::error::ParseError;

#[derive(Debug, Clone, Copy)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: Oid<'a>,
    /// Raw parameters TLV (tag + length + value), or None if absent / NULL.
    pub parameters: Option<&'a [u8]>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// Parse an AlgorithmIdentifier from a sub-reader positioned at its
    /// outer SEQUENCE tag.
    pub fn parse(reader: &mut DerReader<'a>) -> Result<Self, ParseError> {
        let mut inner = reader.expect_constructed(tag::TAG_SEQUENCE)?;
        Self::parse_inner(&mut inner)
    }

    /// Parse contents of an already-unwrapped AlgorithmIdentifier SEQUENCE.
    pub fn parse_inner(inner: &mut DerReader<'a>) -> Result<Self, ParseError> {
        let oid_value = inner.expect(tag::TAG_OBJECT_IDENTIFIER)?;
        let algorithm = Oid::from_bytes(oid_value)?;

        // Parameters are optional and the most common form is a NULL TLV
        // (`05 00`). We expose the raw TLV when present so the caller can
        // re-parse for non-NULL parameters such as EC named curves.
        let parameters = if inner.is_empty() {
            None
        } else {
            let Tlv { raw, tag: t, .. } = inner.read_tlv()?;
            // Treat explicit NULL the same as absent — callers don't care.
            if t == tag::TAG_NULL {
                None
            } else {
                Some(raw)
            }
        };
        inner.end()?;
        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::oid::OID_RSA_ENCRYPTION;

    #[test]
    fn rsa_with_null_parameters() {
        // SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        let mut bytes = vec![tag::TAG_SEQUENCE, 0x0d, tag::TAG_OBJECT_IDENTIFIER, 0x09];
        bytes.extend_from_slice(OID_RSA_ENCRYPTION);
        bytes.extend_from_slice(&[tag::TAG_NULL, 0x00]);

        let mut r = DerReader::new(&bytes);
        let alg = AlgorithmIdentifier::parse(&mut r).unwrap();
        assert_eq!(alg.algorithm.to_id_string(), "1.2.840.113549.1.1.1");
        assert!(alg.parameters.is_none());
    }

    #[test]
    fn ec_with_curve_parameters() {
        // SEQUENCE { OID id-ecPublicKey, OID secp256r1 }
        let alg_oid = crate::der::oid::OID_EC_PUBLIC_KEY;
        let curve_oid = crate::der::oid::OID_SECP256R1;
        let mut bytes = vec![tag::TAG_SEQUENCE, 0];
        bytes.push(tag::TAG_OBJECT_IDENTIFIER);
        bytes.push(alg_oid.len() as u8);
        bytes.extend_from_slice(alg_oid);
        bytes.push(tag::TAG_OBJECT_IDENTIFIER);
        bytes.push(curve_oid.len() as u8);
        bytes.extend_from_slice(curve_oid);
        let inner_len = bytes.len() - 2;
        bytes[1] = inner_len as u8;

        let mut r = DerReader::new(&bytes);
        let alg = AlgorithmIdentifier::parse(&mut r).unwrap();
        assert_eq!(alg.algorithm.to_id_string(), "1.2.840.10045.2.1");

        // The parameters field should hold the curve OID's full TLV.
        let params = alg.parameters.expect("EC params present");
        assert_eq!(params[0], tag::TAG_OBJECT_IDENTIFIER);
        assert_eq!(params[1] as usize, curve_oid.len());
        assert_eq!(&params[2..], curve_oid);
    }
}
