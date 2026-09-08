// rust_certinfo/src/crypto/eddsa.rs
//
// PureEdDSA verification (RFC 8032). Ed25519 (§5.1) is implemented here;
// Ed448 (§5.2) reports as unsupported until it lands.
//
// The hashing lives in Python, so the caller passes the challenge
// `k = SHA-512(R || A || M)` (RFC 8032 §5.1.7 step 2) and only the group
// arithmetic happens here. Points are kept in the extended twisted
// Edwards coordinates of §5.1.4, where `(X, Y, Z, T)` stands for
// `x = X/Z`, `y = Y/Z`, and `x*y = T/Z`, so the whole verification needs
// no field inversion: the final comparison cross-multiplies by the two
// `Z` values instead.

use crate::crypto::bigint::BigUint;
use crate::crypto::VerifyError;

/// The Edwards curve an EdDSA signature is over (RFC 8032 §5.1, §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdCurve {
    Ed25519,
    Ed448,
}

/// Verify a PureEdDSA signature.
///
/// `public_key` is the raw `subjectPublicKey` bits of an RFC 8410
/// SubjectPublicKeyInfo, `r` and `s` are the two halves of the signature,
/// and `k` is the challenge hash `H(R || A || M)` of RFC 8032 §5.1.7
/// step 2, unreduced (this reduces it mod the group order).
///
/// `Ok(false)` means the signature was checked and is wrong;
/// `Err(Malformed)` that the inputs are the wrong length or that a point
/// does not decode; `Err(Unsupported)` that the curve is not implemented.
pub fn verify(
    curve: EdCurve,
    public_key: &[u8],
    r: &[u8],
    s: &[u8],
    k: &[u8],
) -> Result<bool, VerifyError> {
    match curve {
        EdCurve::Ed25519 => Ed25519::new().verify(public_key, r, s, k),
        EdCurve::Ed448 => Err(VerifyError::Unsupported(
            "Ed448 signature verification".into(),
        )),
    }
}

/// A curve constant from its big-endian hex digits. Only ever called on
/// the literals below, so a bad digit is a bug in this file.
fn hex(text: &str) -> BigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("curve constant"))
        .collect();
    BigUint::from_be_bytes(&bytes)
}

/// An integer in the little-endian encoding RFC 8032 §5.1.2 uses for
/// coordinates and scalars.
fn little_endian(bytes: &[u8]) -> BigUint {
    let mut be: Vec<u8> = bytes.to_vec();
    be.reverse();
    BigUint::from_be_bytes(&be)
}

/// Arithmetic mod `p`, reducing after every operation so no intermediate
/// ever grows past twice the modulus.
struct Field<'a> {
    p: &'a BigUint,
}

impl Field<'_> {
    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.add(b).rem(self.p)
    }

    /// `a - b mod p`. `BigUint` is unsigned, so `p` is added first; both
    /// operands are already reduced, so `a + p` never underflows.
    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.add(self.p).sub(b).rem(self.p)
    }

    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.mul(b).rem(self.p)
    }

    fn sqr(&self, a: &BigUint) -> BigUint {
        self.mul(a, a)
    }

    fn pow(&self, a: &BigUint, exponent: &BigUint) -> BigUint {
        a.mod_pow(exponent, self.p)
    }

    fn neg(&self, a: &BigUint) -> BigUint {
        self.sub(&BigUint::zero(), a)
    }
}

/// A point in the extended twisted Edwards coordinates of RFC 8032
/// §5.1.4: `x = X/Z`, `y = Y/Z`, and `x*y = T/Z`.
#[derive(Clone)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

/// The edwards25519 group: the field prime, the curve constant, the order
/// of the base point, and the two exponents the square root of §5.1.3
/// needs (RFC 8032 §5.1).
struct Ed25519 {
    /// p = 2^255 - 19.
    p: BigUint,
    /// d = -121665/121666 mod p.
    d: BigUint,
    /// 2*d mod p, the factor the §5.1.4 addition formula applies to T1*T2.
    d2: BigUint,
    /// L = 2^252 + 27742317777372353535851937790883648493, the prime order
    /// of the base point B.
    l: BigUint,
    /// (p-5)/8 = 2^252 - 3, the exponent of the §5.1.3 square-root formula.
    /// A constant rather than a division, since p is a constant too.
    sqrt_exponent: BigUint,
    /// sqrt(-1) = 2^((p-1)/4) mod p, which turns a square root of `-u`
    /// into one of `u` (§5.1.3 step 3). Precomputed for the same reason.
    sqrt_minus_one: BigUint,
    /// The base point B: y = 4/5 mod p with the even x, i.e. the encoding
    /// `5866666666666666666666666666666666666666666666666666666666666666`.
    base: Point,
}

impl Ed25519 {
    fn new() -> Self {
        let p = hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
        let d = hex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
        let d2 = d.add(&d).rem(&p);
        let base_x = hex("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
        let base_y = hex("6666666666666666666666666666666666666666666666666666666666666658");
        let base_t = base_x.mul(&base_y).rem(&p);
        Self {
            d,
            d2,
            l: hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
            sqrt_exponent: hex("0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"),
            sqrt_minus_one: hex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0"),
            base: Point {
                x: base_x,
                y: base_y,
                z: BigUint::one(),
                t: base_t,
            },
            p,
        }
    }

    fn field(&self) -> Field<'_> {
        Field { p: &self.p }
    }

    /// The neutral element, `(0, 1, 1, 0)` in extended coordinates.
    fn neutral(&self) -> Point {
        Point {
            x: BigUint::zero(),
            y: BigUint::one(),
            z: BigUint::one(),
            t: BigUint::zero(),
        }
    }

    /// Recover a point from its 32-byte encoding (RFC 8032 §5.1.3): the
    /// low 255 bits are `y` little-endian and the top bit is the sign of
    /// `x`, which is recovered from the curve equation as
    /// `x = sqrt((y^2 - 1) / (d*y^2 + 1))`.
    fn decode_point(&self, encoded: &[u8; 32]) -> Result<Point, VerifyError> {
        let f = self.field();
        let mut le = *encoded;
        let x_is_odd = le[31] >> 7 == 1;
        le[31] &= 0x7f;
        let y = little_endian(&le);
        if y >= self.p {
            return Err(VerifyError::Malformed(
                "Ed25519 y coordinate is not a field element",
            ));
        }
        // The square root is x = u * v^3 * (u * v^7)^((p-5)/8) with
        // u = y^2 - 1 and v = d*y^2 + 1, per §5.1.3 step 3.
        let yy = f.sqr(&y);
        let u = f.sub(&yy, &BigUint::one());
        let v = f.add(&f.mul(&self.d, &yy), &BigUint::one());
        let v3 = f.mul(&f.sqr(&v), &v);
        let v7 = f.mul(&f.sqr(&v3), &v);
        let candidate = f.pow(&f.mul(&u, &v7), &self.sqrt_exponent);
        let mut x = f.mul(&f.mul(&u, &v3), &candidate);
        // v*x^2 is u for the root itself and -u when the root is off by
        // sqrt(-1); anything else means y names no point on the curve.
        let vxx = f.mul(&v, &f.sqr(&x));
        if vxx != u {
            if vxx != f.neg(&u) {
                return Err(VerifyError::Malformed("Ed25519 point is not on the curve"));
            }
            x = f.mul(&x, &self.sqrt_minus_one);
        }
        if x.is_zero() && x_is_odd {
            // x = 0 has one encoding, so a set sign bit is not canonical.
            return Err(VerifyError::Malformed(
                "Ed25519 point has a non-canonical sign bit",
            ));
        }
        if x.is_odd() != x_is_odd {
            x = f.neg(&x);
        }
        let t = f.mul(&x, &y);
        Ok(Point {
            x,
            y,
            z: BigUint::one(),
            t,
        })
    }

    /// The unified addition of RFC 8032 §5.1.4, which is complete on a
    /// twisted Edwards curve, so doubling is just `add(q, q)`.
    fn add(&self, q1: &Point, q2: &Point) -> Point {
        let f = self.field();
        let a = f.mul(&f.sub(&q1.y, &q1.x), &f.sub(&q2.y, &q2.x));
        let b = f.mul(&f.add(&q1.y, &q1.x), &f.add(&q2.y, &q2.x));
        let c = f.mul(&f.mul(&q1.t, &self.d2), &q2.t);
        let d = f.mul(&q1.z, &f.add(&q2.z, &q2.z));
        let e = f.sub(&b, &a);
        let g = f.sub(&d, &c);
        let h = f.add(&d, &c);
        let i = f.add(&b, &a);
        Point {
            x: f.mul(&e, &g),
            y: f.mul(&h, &i),
            z: f.mul(&g, &h),
            t: f.mul(&e, &i),
        }
    }

    /// `[scalar]q`, left to right over the bits of the scalar.
    fn scalar_mul(&self, scalar: &BigUint, q: &Point) -> Point {
        let mut acc = self.neutral();
        for index in (0..scalar.bit_len()).rev() {
            acc = self.add(&acc, &acc);
            if scalar.bit(index) {
                acc = self.add(&acc, q);
            }
        }
        acc
    }

    /// Projective equality: two triples name the same affine point when
    /// `X1*Z2 == X2*Z1` and `Y1*Z2 == Y2*Z1`.
    fn same_point(&self, q1: &Point, q2: &Point) -> bool {
        let f = self.field();
        f.mul(&q1.x, &q2.z) == f.mul(&q2.x, &q1.z) && f.mul(&q1.y, &q2.z) == f.mul(&q2.y, &q1.z)
    }

    /// RFC 8032 §5.1.7 step 3, in the cofactorless form the same section
    /// permits: check `[s]B = R + [k]A` rather than its eightfold.
    fn verify(&self, public_key: &[u8], r: &[u8], s: &[u8], k: &[u8]) -> Result<bool, VerifyError> {
        let encoded_a: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| VerifyError::Malformed("Ed25519 public key length"))?;
        let encoded_r: &[u8; 32] = r
            .try_into()
            .map_err(|_| VerifyError::Malformed("Ed25519 signature length"))?;
        if s.len() != 32 {
            return Err(VerifyError::Malformed("Ed25519 signature length"));
        }
        if k.len() != 64 {
            return Err(VerifyError::Malformed("Ed25519 challenge length"));
        }
        let a = self.decode_point(encoded_a)?;
        let big_r = self.decode_point(encoded_r)?;
        // s must be the canonical little-endian encoding of a scalar below
        // the group order; anything larger is a malleable re-encoding of
        // some other signature and is simply wrong, not malformed.
        let s = little_endian(s);
        if s >= self.l {
            return Ok(false);
        }
        let k = little_endian(k).rem(&self.l);
        let left = self.scalar_mul(&s, &self.base);
        let right = self.add(&big_r, &self.scalar_mul(&k, &a));
        Ok(self.same_point(&left, &right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::VerifyError;

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("test vector"))
            .collect()
    }

    /// One RFC 8032 §7.1 vector: public key, signature, and the challenge
    /// `SHA-512(R || A || M)` computed from them with `hashlib`.
    struct Vector {
        public_key: &'static str,
        signature: &'static str,
        challenge: &'static str,
    }

    /// RFC 8032 §7.1 test 1 (empty message).
    const TEST_1: Vector = Vector {
        public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        challenge: "2771062b6b536fe7ffbdda0320c3827b035df10d284df3f08222f04dbca7a4c20ef15bdc988a22c7207411377c33f2ac09b1e86a046234283768ee7ba03c0e9f",
    };

    /// RFC 8032 §7.1 test 2 (one-byte message `72`).
    const TEST_2: Vector = Vector {
        public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        challenge: "a271df0d2b0d03bd17b4ed9a4b6afddf2e73287fd630f1a137d87ce873a591cc31b6dd852a98b5dd1226fe993d8228278ceba21f80b8fc95986a70d71edf3faf",
    };

    /// RFC 8032 §7.1 test 3 (two-byte message `af82`).
    const TEST_3: Vector = Vector {
        public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        challenge: "09bfb4ff1993f38f2ef65699934a8b64c0325867f858059b95bca199f78dc09e544857aeb4abddc6e35660da2867ab5963135ffef60d242dbfce0a85fbc362bf",
    };

    /// RFC 8032 §7.1 "SHA(abc)" test, whose message is 64 bytes long.
    const TEST_SHA_ABC: Vector = Vector {
        public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        challenge: "5ea8a61daa7bb05bc0c58f108ad46822e2ee812b418666d4b53e8160c268422edfcf89131f99e5a11f6df1c58753050b56122c166df6708fa961d63341e7aae5",
    };

    fn check(vector: &Vector) -> Result<bool, VerifyError> {
        let key = hex_bytes(vector.public_key);
        let signature = hex_bytes(vector.signature);
        let challenge = hex_bytes(vector.challenge);
        verify(
            EdCurve::Ed25519,
            &key,
            &signature[..32],
            &signature[32..],
            &challenge,
        )
    }

    #[test]
    fn rfc8032_vectors_verify() {
        for vector in [&TEST_1, &TEST_2, &TEST_3, &TEST_SHA_ABC] {
            assert_eq!(check(vector), Ok(true), "{}", vector.public_key);
        }
    }

    #[test]
    fn a_different_challenge_does_not_verify() {
        let key = hex_bytes(TEST_1.public_key);
        let signature = hex_bytes(TEST_1.signature);
        let mut challenge = hex_bytes(TEST_1.challenge);
        challenge[7] ^= 1;
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key,
                &signature[..32],
                &signature[32..],
                &challenge,
            ),
            Ok(false)
        );
    }

    #[test]
    fn a_scalar_at_or_above_the_group_order_does_not_verify() {
        // RFC 8032 §5.1.7 requires s < L; L itself is the smallest
        // non-canonical encoding, and Wycheproof's "SignatureMalleability"
        // vectors are exactly this shape.
        let key = hex_bytes(TEST_1.public_key);
        let signature = hex_bytes(TEST_1.signature);
        let challenge = hex_bytes(TEST_1.challenge);
        let order = hex_bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        assert_eq!(
            verify(EdCurve::Ed25519, &key, &signature[..32], &order, &challenge,),
            Ok(false)
        );
    }

    #[test]
    fn a_public_key_whose_y_is_not_a_field_element_is_malformed() {
        // 2^255 - 1 with the sign bit cleared, so y > p = 2^255 - 19.
        let mut key = vec![0xff; 32];
        key[31] = 0x7f;
        let signature = hex_bytes(TEST_1.signature);
        let challenge = hex_bytes(TEST_1.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key,
                &signature[..32],
                &signature[32..],
                &challenge,
            ),
            Err(VerifyError::Malformed(
                "Ed25519 y coordinate is not a field element"
            ))
        );
    }

    #[test]
    fn a_point_off_the_curve_is_malformed() {
        // y = 2 has no matching x on edwards25519.
        let mut key = vec![0u8; 32];
        key[0] = 2;
        let signature = hex_bytes(TEST_1.signature);
        let challenge = hex_bytes(TEST_1.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key,
                &signature[..32],
                &signature[32..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed25519 point is not on the curve"))
        );
    }

    #[test]
    fn wrong_lengths_are_malformed() {
        let key = hex_bytes(TEST_1.public_key);
        let signature = hex_bytes(TEST_1.signature);
        let challenge = hex_bytes(TEST_1.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key[..31],
                &signature[..32],
                &signature[32..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed25519 public key length"))
        );
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key,
                &signature[..31],
                &signature[32..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed25519 signature length"))
        );
        assert_eq!(
            verify(
                EdCurve::Ed25519,
                &key,
                &signature[..32],
                &signature[32..],
                &challenge[..63],
            ),
            Err(VerifyError::Malformed("Ed25519 challenge length"))
        );
    }

    #[test]
    fn ed448_is_not_implemented_yet() {
        assert!(matches!(
            verify(EdCurve::Ed448, &[], &[], &[], &[]),
            Err(VerifyError::Unsupported(_))
        ));
    }
}
