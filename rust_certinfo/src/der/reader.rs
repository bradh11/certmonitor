// rust_certinfo/src/der/reader.rs
//
// Strict-DER TLV cursor. The reader walks a `&[u8]` buffer one Tag-Length-
// Value triple at a time, validates DER canonicalization rules on the way
// (no indefinite length, no over-long length encodings, bounds checks
// against the parent slice on every read), and never panics on malformed
// input. All errors flow through `ParseError`.

use crate::error::ParseError;

/// One DER Tag-Length-Value element.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// Bytes of the value field, NOT including the tag and length prefix.
    pub value: &'a [u8],
    /// Bytes of the entire TLV, including tag and length prefix. Used when
    /// the caller needs the raw DER (e.g. `Name::raw`, `SPKI::raw`).
    pub raw: &'a [u8],
}

/// Cursor over a DER byte slice.
#[derive(Debug, Clone, Copy)]
pub struct DerReader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Assert there are no unread bytes, otherwise return `TrailingBytes`.
    pub fn end(self) -> Result<(), ParseError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes)
        }
    }

    /// Peek the next tag byte without advancing.
    pub fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Read the next TLV. Advances the cursor past the entire element.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, ParseError> {
        let start = self.pos;
        let tag = self.read_byte()?;
        let length = self.read_length()?;
        let value_start = self.pos;
        let value_end = value_start
            .checked_add(length)
            .ok_or(ParseError::IntegerOverflow)?;
        if value_end > self.input.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let value = &self.input[value_start..value_end];
        let raw = &self.input[start..value_end];
        self.pos = value_end;
        Ok(Tlv { tag, value, raw })
    }

    /// Read the next TLV and require that its tag matches `expected`.
    /// Returns the value slice (not including tag/length).
    pub fn expect(&mut self, expected: u8) -> Result<&'a [u8], ParseError> {
        let tlv = self.read_tlv()?;
        if tlv.tag != expected {
            return Err(ParseError::UnexpectedTag {
                expected,
                got: tlv.tag,
            });
        }
        Ok(tlv.value)
    }

    /// Like `expect`, but also returns a sub-reader scoped to the value
    /// bytes — convenient for parsing the contents of a SEQUENCE/SET.
    pub fn expect_constructed(&mut self, expected: u8) -> Result<DerReader<'a>, ParseError> {
        let value = self.expect(expected)?;
        Ok(DerReader::new(value))
    }

    /// Read a single byte from the cursor.
    fn read_byte(&mut self) -> Result<u8, ParseError> {
        let b = *self.input.get(self.pos).ok_or(ParseError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// DER length octets (X.690 §8.1.3).
    ///
    /// Short form: single byte 0x00..=0x7f.
    /// Long form: first byte 0x80 | N where N is the number of length
    ///   bytes that follow; 0x80 alone is indefinite-length and forbidden
    ///   in DER. The length value itself must use the minimum number of
    ///   bytes — both `read_length` and the call sites enforce this.
    fn read_length(&mut self) -> Result<usize, ParseError> {
        let first = self.read_byte()?;
        if first < 0x80 {
            return Ok(first as usize);
        }
        if first == 0x80 {
            return Err(ParseError::IndefiniteLengthForbidden);
        }
        let n = (first & 0x7f) as usize;
        // Reject pathological length-of-length values. A `usize` on every
        // supported platform is at most 8 bytes; we cap at 4 because no
        // legitimate certificate has a >4 GiB element.
        if n == 0 || n > 4 {
            return Err(ParseError::NonCanonicalLength);
        }
        let mut value: usize = 0;
        let length_bytes_start = self.pos;
        for _ in 0..n {
            let b = self.read_byte()? as usize;
            value = value.checked_shl(8).ok_or(ParseError::IntegerOverflow)?;
            value = value.checked_add(b).ok_or(ParseError::IntegerOverflow)?;
        }
        // First length byte must be non-zero (no leading-zero padding) and
        // the resulting value must be ≥ 128 (otherwise short form should
        // have been used).
        if self.input[length_bytes_start] == 0 || value < 0x80 {
            return Err(ParseError::NonCanonicalLength);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_length() {
        // OCTET STRING with 5-byte content "hello"
        let bytes = [0x04, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut r = DerReader::new(&bytes);
        let v = r.expect(0x04).unwrap();
        assert_eq!(v, b"hello");
        assert!(r.end().is_ok());
    }

    #[test]
    fn long_form_length() {
        // OCTET STRING with 200-byte content
        let mut bytes = vec![0x04, 0x81, 200];
        bytes.extend_from_slice(&[0u8; 200]);
        let mut r = DerReader::new(&bytes);
        let v = r.expect(0x04).unwrap();
        assert_eq!(v.len(), 200);
    }

    #[test]
    fn indefinite_length_rejected() {
        let bytes = [0x30, 0x80, 0x00, 0x00];
        let mut r = DerReader::new(&bytes);
        assert_eq!(
            r.read_tlv().unwrap_err(),
            ParseError::IndefiniteLengthForbidden
        );
    }

    #[test]
    fn long_form_with_value_under_128_rejected() {
        // 0x81 0x42 says "1-byte length, value 0x42" — but 0x42 < 128 so
        // short form was required.
        let bytes = [0x04, 0x81, 0x42];
        let mut r = DerReader::new(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), ParseError::NonCanonicalLength);
    }

    #[test]
    fn long_form_with_leading_zero_rejected() {
        // 0x82 0x00 0x80 says "2-byte length, value 0x0080" — leading
        // zero is forbidden in DER long form.
        let bytes = [0x04, 0x82, 0x00, 0x80];
        let mut r = DerReader::new(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), ParseError::NonCanonicalLength);
    }

    #[test]
    fn truncated_value_rejected() {
        let bytes = [0x04, 0x05, b'h', b'e'];
        let mut r = DerReader::new(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), ParseError::UnexpectedEof);
    }

    #[test]
    fn unexpected_tag() {
        let bytes = [0x04, 0x01, 0x00];
        let mut r = DerReader::new(&bytes);
        assert_eq!(
            r.expect(0x02).unwrap_err(),
            ParseError::UnexpectedTag {
                expected: 0x02,
                got: 0x04,
            }
        );
    }

    #[test]
    fn trailing_bytes() {
        let bytes = [0x04, 0x01, 0x00, 0xff];
        let mut r = DerReader::new(&bytes);
        let _ = r.read_tlv().unwrap();
        assert_eq!(r.end().unwrap_err(), ParseError::TrailingBytes);
    }
}
