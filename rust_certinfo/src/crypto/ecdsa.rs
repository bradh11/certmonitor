// rust_certinfo/src/crypto/ecdsa.rs
//
// ECDSA verification over the NIST curves P-256 and P-384 (FIPS 186-4,
// SEC 1 §4.1.4). Points are kept in Jacobian coordinates so the only field
// inversion is the final one. Both curves have a = -3, which the doubling
// formula relies on. Arithmetic is the generic `BigUint` with reduction
// after every step: slow by cryptographic-library standards, fast enough
// to verify a handful of OCSP responses.

use crate::crypto::bigint::BigUint;
use crate::crypto::VerifyError;
use crate::der::{tag, DerReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

struct Params {
    p: BigUint,
    b: BigUint,
    n: BigUint,
    gx: BigUint,
    gy: BigUint,
    /// Field element size in bytes.
    size: usize,
}

fn hex(text: &str) -> BigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("curve constant"))
        .collect();
    BigUint::from_be_bytes(&bytes)
}

impl Curve {
    fn params(self) -> Params {
        match self {
            Curve::P256 => Params {
                p: hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                n: hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                gx: hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                gy: hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                size: 32,
            },
            Curve::P384 => Params {
                p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                b: hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
                n: hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
                gx: hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
                gy: hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
                size: 48,
            },
        }
    }
}

/// A point in Jacobian coordinates; `z == 0` is the point at infinity.
#[derive(Clone)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

struct Field<'a> {
    p: &'a BigUint,
}

impl Field<'_> {
    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.add(b).rem(self.p)
    }

    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.add(self.p).sub(b).rem(self.p)
    }

    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.mul(b).rem(self.p)
    }

    fn sqr(&self, a: &BigUint) -> BigUint {
        self.mul(a, a)
    }

    fn small(&self, a: &BigUint, k: u64) -> BigUint {
        a.mul(&BigUint::from_u64(k)).rem(self.p)
    }

    /// Multiplicative inverse by Fermat: a^(p-2) mod p.
    fn inv(&self, a: &BigUint) -> BigUint {
        a.mod_pow(&self.p.sub(&BigUint::from_u64(2)), self.p)
    }

    fn infinity(&self) -> Point {
        Point {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    /// dbl-2001-b for a = -3.
    fn double(&self, q: &Point) -> Point {
        if q.z.is_zero() {
            return q.clone();
        }
        let delta = self.sqr(&q.z);
        let gamma = self.sqr(&q.y);
        let beta = self.mul(&q.x, &gamma);
        let alpha = self.small(
            &self.mul(&self.sub(&q.x, &delta), &self.add(&q.x, &delta)),
            3,
        );
        let x3 = self.sub(&self.sqr(&alpha), &self.small(&beta, 8));
        let z3 = self.sub(&self.sub(&self.sqr(&self.add(&q.y, &q.z)), &gamma), &delta);
        let y3 = self.sub(
            &self.mul(&alpha, &self.sub(&self.small(&beta, 4), &x3)),
            &self.small(&self.sqr(&gamma), 8),
        );
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// add-2007-bl.
    fn add_points(&self, a: &Point, b: &Point) -> Point {
        if a.z.is_zero() {
            return b.clone();
        }
        if b.z.is_zero() {
            return a.clone();
        }
        let z1z1 = self.sqr(&a.z);
        let z2z2 = self.sqr(&b.z);
        let u1 = self.mul(&a.x, &z2z2);
        let u2 = self.mul(&b.x, &z1z1);
        let s1 = self.mul(&self.mul(&a.y, &b.z), &z2z2);
        let s2 = self.mul(&self.mul(&b.y, &a.z), &z1z1);
        let h = self.sub(&u2, &u1);
        let r = self.small(&self.sub(&s2, &s1), 2);
        if h.is_zero() {
            if r.is_zero() {
                return self.double(a);
            }
            return self.infinity();
        }
        let i = self.sqr(&self.small(&h, 2));
        let j = self.mul(&h, &i);
        let v = self.mul(&u1, &i);
        let x3 = self.sub(&self.sub(&self.sqr(&r), &j), &self.small(&v, 2));
        let y3 = self.sub(
            &self.mul(&r, &self.sub(&v, &x3)),
            &self.small(&self.mul(&s1, &j), 2),
        );
        let z3 = self.mul(
            &self.sub(&self.sub(&self.sqr(&self.add(&a.z, &b.z)), &z1z1), &z2z2),
            &h,
        );
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn scalar_mul(&self, k: &BigUint, q: &Point) -> Point {
        let mut result = self.infinity();
        for i in (0..k.bit_len()).rev() {
            result = self.double(&result);
            if k.bit(i) {
                result = self.add_points(&result, q);
            }
        }
        result
    }

    /// Affine x coordinate, or `None` for the point at infinity.
    fn affine_x(&self, q: &Point) -> Option<BigUint> {
        if q.z.is_zero() {
            return None;
        }
        let zinv = self.inv(&q.z);
        Some(self.mul(&q.x, &self.sqr(&zinv)))
    }

    fn on_curve(&self, x: &BigUint, y: &BigUint, b: &BigUint) -> bool {
        // y^2 == x^3 - 3x + b
        let lhs = self.sqr(y);
        let rhs = self.add(&self.sub(&self.mul(&self.sqr(x), x), &self.small(x, 3)), b);
        lhs == rhs
    }
}

/// An affine public key point, decoded from an uncompressed SEC 1 encoding.
#[derive(Debug)]
pub struct PublicKey {
    curve: Curve,
    x: BigUint,
    y: BigUint,
}

impl PublicKey {
    /// Parse the BIT STRING contents of an id-ecPublicKey SubjectPublicKeyInfo.
    pub fn from_sec1(curve: Curve, bytes: &[u8]) -> Result<Self, VerifyError> {
        let params = curve.params();
        if bytes.len() != 1 + 2 * params.size || bytes[0] != 0x04 {
            return Err(VerifyError::Unsupported(
                "EC point encoding (only uncompressed points are supported)".into(),
            ));
        }
        let x = BigUint::from_be_bytes(&bytes[1..1 + params.size]);
        let y = BigUint::from_be_bytes(&bytes[1 + params.size..]);
        let field = Field { p: &params.p };
        if x >= params.p || y >= params.p || !field.on_curve(&x, &y, &params.b) {
            return Err(VerifyError::Malformed("EC public key is not on the curve"));
        }
        Ok(Self { curve, x, y })
    }
}

/// Parse `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
fn parse_signature(der: &[u8]) -> Result<(BigUint, BigUint), VerifyError> {
    let mut top = DerReader::new(der);
    let mut seq = top
        .expect_constructed(tag::TAG_SEQUENCE)
        .map_err(|_| VerifyError::Malformed("ECDSA signature"))?;
    let r = seq
        .expect(tag::TAG_INTEGER)
        .map_err(|_| VerifyError::Malformed("ECDSA r"))?;
    let s = seq
        .expect(tag::TAG_INTEGER)
        .map_err(|_| VerifyError::Malformed("ECDSA s"))?;
    seq.end()
        .map_err(|_| VerifyError::Malformed("ECDSA signature"))?;
    top.end()
        .map_err(|_| VerifyError::Malformed("ECDSA signature"))?;
    // r and s are positive INTEGERs; a sign bit or padding zeros is not DER.
    let r = BigUint::from_der_positive(r).ok_or(VerifyError::Malformed("ECDSA r"))?;
    let s = BigUint::from_der_positive(s).ok_or(VerifyError::Malformed("ECDSA s"))?;
    Ok((r, s))
}

/// Verify a DER-encoded ECDSA signature over `digest` with `key`.
pub fn verify(key: &PublicKey, digest: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    let params = key.curve.params();
    let (r, s) = parse_signature(signature)?;
    if r.is_zero() || s.is_zero() || r >= params.n || s >= params.n {
        return Ok(false);
    }
    // e is the leftmost bit_len(n) bits of the digest.
    let mut e = BigUint::from_be_bytes(digest);
    let excess = (digest.len() * 8).saturating_sub(params.n.bit_len());
    if excess > 0 {
        let divisor = BigUint::one().mul(&BigUint::from_u64(1u64 << excess.min(63)));
        let mut remaining = excess;
        e = e.divrem(&divisor).0;
        remaining = remaining.saturating_sub(excess.min(63));
        while remaining > 0 {
            let step = remaining.min(63);
            e = e.divrem(&BigUint::from_u64(1u64 << step)).0;
            remaining -= step;
        }
    }
    let scalar = Field { p: &params.n };
    let w = scalar.inv(&s);
    let u1 = scalar.mul(&e, &w);
    let u2 = scalar.mul(&r, &w);

    let field = Field { p: &params.p };
    let g = Point {
        x: params.gx.clone(),
        y: params.gy.clone(),
        z: BigUint::one(),
    };
    let q = Point {
        x: key.x.clone(),
        y: key.y.clone(),
        z: BigUint::one(),
    };
    let sum = field.add_points(&field.scalar_mul(&u1, &g), &field.scalar_mul(&u2, &q));
    match field.affine_x(&sum) {
        None => Ok(false),
        Some(x) => Ok(x.rem(&params.n) == r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_vectors::{
        hex as hex_bytes, DIGEST256, DIGEST384, P256_SIG, P256_SPKI, P384_SIG, P384_SPKI,
    };
    use crate::x509::spki::SubjectPublicKeyInfo;

    fn key(curve: Curve, spki_hex: &str) -> PublicKey {
        let der = hex_bytes(spki_hex);
        let mut reader = DerReader::new(&der);
        let spki = SubjectPublicKeyInfo::parse(&mut reader).unwrap();
        PublicKey::from_sec1(curve, spki.subject_public_key).unwrap()
    }

    #[test]
    fn rfc6979_p256_sha256_sample() {
        // RFC 6979 A.2.5, message "sample", SHA-256.
        let mut point = vec![0x04];
        point.extend(hex_bytes(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        ));
        point.extend(hex_bytes(
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        ));
        let key = PublicKey::from_sec1(Curve::P256, &point).unwrap();
        let digest = hex_bytes("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
        let signature = der_signature(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        );
        assert!(verify(&key, &digest, &signature).unwrap());
    }

    #[test]
    fn openssl_signatures_verify_on_both_curves() {
        let k256 = key(Curve::P256, P256_SPKI);
        assert!(verify(&k256, &hex_bytes(DIGEST256), &hex_bytes(P256_SIG)).unwrap());
        let k384 = key(Curve::P384, P384_SPKI);
        assert!(verify(&k384, &hex_bytes(DIGEST384), &hex_bytes(P384_SIG)).unwrap());
        // A longer digest than the curve order is truncated (SHA-384 on P-256).
        assert!(!verify(&k256, &hex_bytes(DIGEST384), &hex_bytes(P256_SIG)).unwrap());
    }

    #[test]
    fn tampering_and_bad_inputs_are_rejected() {
        let k256 = key(Curve::P256, P256_SPKI);
        let mut digest = hex_bytes(DIGEST256);
        digest[0] ^= 1;
        assert!(!verify(&k256, &digest, &hex_bytes(P256_SIG)).unwrap());
        let mut signature = hex_bytes(P256_SIG);
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(!verify(&k256, &hex_bytes(DIGEST256), &signature).unwrap());
        assert!(verify(&k256, &hex_bytes(DIGEST256), &[0x30, 0x00]).is_err());
        // Wycheproof "MissingZero" and "prepending 0's": non-canonical INTEGERs.
        let good = hex_bytes(P256_SIG);
        assert_eq!(good[36..39], [0x02, 0x21, 0x00]); // s is 0x21 bytes with a leading 0
        let mut missing_zero = good.clone();
        missing_zero.remove(38);
        missing_zero[37] = 0x20;
        missing_zero[1] -= 1;
        assert!(verify(&k256, &hex_bytes(DIGEST256), &missing_zero).is_err());
        let mut padded = good.clone();
        padded.insert(4, 0x00);
        padded[3] += 1;
        padded[1] += 1;
        assert!(verify(&k256, &hex_bytes(DIGEST256), &padded).is_err());
        assert!(verify(&k256, &hex_bytes(DIGEST256), &[0x04, 0x00]).is_err());
        // r or s outside [1, n-1] fails without any curve arithmetic.
        let zero_r = der_signature("00", "01");
        assert!(!verify(&k256, &hex_bytes(DIGEST256), &zero_r).unwrap());
        let huge_s = der_signature(
            "01",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        );
        assert!(!verify(&k256, &hex_bytes(DIGEST256), &huge_s).unwrap());
    }

    #[test]
    fn points_off_the_curve_and_compressed_points_are_rejected() {
        let mut point = vec![0x04];
        point.extend([0x01; 64]);
        assert_eq!(
            PublicKey::from_sec1(Curve::P256, &point).unwrap_err(),
            VerifyError::Malformed("EC public key is not on the curve")
        );
        let compressed = [vec![0x02], vec![0x01; 32]].concat();
        assert!(matches!(
            PublicKey::from_sec1(Curve::P256, &compressed).unwrap_err(),
            VerifyError::Unsupported(_)
        ));
    }

    fn der_signature(r: &str, s: &str) -> Vec<u8> {
        fn integer(hex_text: &str) -> Vec<u8> {
            let mut bytes = hex_bytes(hex_text);
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
            let mut out = vec![0x02, bytes.len() as u8];
            out.extend(bytes);
            out
        }
        let body = [integer(r), integer(s)].concat();
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }
}
