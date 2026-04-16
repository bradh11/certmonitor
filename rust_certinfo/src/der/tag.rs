// rust_certinfo/src/der/tag.rs
//
// DER tag constants and helpers. We deliberately operate on raw u8 tag
// bytes rather than building a richer Tag struct — the X.509 structures
// we parse only need universal types and a handful of context-specific
// tags, so byte comparison is the simplest correct approach.

// Universal types (RFC 6025 §8.1 / X.690 §8.1.2.2)
pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_TELETEX_STRING: u8 = 0x14; // a.k.a. T61String
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_UNIVERSAL_STRING: u8 = 0x1c;
pub const TAG_BMP_STRING: u8 = 0x1e;

// Constructed types
pub const TAG_SEQUENCE: u8 = 0x30; // SEQUENCE / SEQUENCE OF
pub const TAG_SET: u8 = 0x31; // SET / SET OF

// Context-specific tags used by Certificate / TBSCertificate.
// In RFC 5280 these are written as [0], [1], [2], [3] EXPLICIT.
pub const CONTEXT_CONSTRUCTED_0: u8 = 0xa0; // [0] EXPLICIT (version)
pub const CONTEXT_CONSTRUCTED_3: u8 = 0xa3; // [3] EXPLICIT (extensions)
                                            // IMPLICIT [1] / [2] for issuer/subject unique IDs are matched by raw byte
                                            // in the certificate walker; constants for them aren't worth exporting.
