// rust_certinfo/src/crypto/eddsa.rs
//
// PureEdDSA verification (RFC 8032): Ed25519 (§5.1) and Ed448 (§5.2).
//
// The hashing lives in Python, so the caller passes the challenge
// `k = H(R || A || M)` (RFC 8032 §5.1.7 step 2, §5.2.7 step 2) and only
// the group arithmetic happens here.
//
// The two curves share the field helper and the little-endian reader and
// nothing else, because they are not the same shape of curve. edwards25519
// is twisted (`a = -1`), so §5.1.4 gives it extended coordinates
// `(X, Y, Z, T)` standing for `x = X/Z`, `y = Y/Z`, `x*y = T/Z`; edwards448
// is untwisted (`a = 1`), so §5.2.4 gives it plain projective coordinates
// `(X, Y, Z)` and a different addition formula. Neither needs a field
// inversion: both final comparisons cross-multiply by the two `Z` values
// instead.

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
/// step 2 (§5.2.7 step 2 for Ed448), unreduced (this reduces it mod the
/// group order).
///
/// `Ok(false)` means the signature was checked and is wrong, and
/// `Err(Malformed)` that the inputs are the wrong length or that a point
/// does not decode.
pub fn verify(
    curve: EdCurve,
    public_key: &[u8],
    r: &[u8],
    s: &[u8],
    k: &[u8],
) -> Result<bool, VerifyError> {
    match curve {
        EdCurve::Ed25519 => Ed25519::new().verify(public_key, r, s, k),
        EdCurve::Ed448 => Ed448::new().verify(public_key, r, s, k),
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

/// An edwards25519 point in the extended twisted Edwards coordinates of
/// RFC 8032 §5.1.4: `x = X/Z`, `y = Y/Z`, and `x*y = T/Z`.
#[derive(Clone)]
struct ExtendedPoint {
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
    base: ExtendedPoint,
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
            base: ExtendedPoint {
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
    fn neutral(&self) -> ExtendedPoint {
        ExtendedPoint {
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
    fn decode_point(&self, encoded: &[u8; 32]) -> Result<ExtendedPoint, VerifyError> {
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
        Ok(ExtendedPoint {
            x,
            y,
            z: BigUint::one(),
            t,
        })
    }

    /// The unified addition of RFC 8032 §5.1.4, which is complete on a
    /// twisted Edwards curve, so doubling is just `add(q, q)`.
    fn add(&self, q1: &ExtendedPoint, q2: &ExtendedPoint) -> ExtendedPoint {
        let f = self.field();
        // The RFC names these A, B, C, D, E, F, G, H; `d`, `g`, `h`, and
        // `i` here are its D, F, G, and H, since `f` is the field helper
        // and `e` is already taken by E.
        let a = f.mul(&f.sub(&q1.y, &q1.x), &f.sub(&q2.y, &q2.x));
        let b = f.mul(&f.add(&q1.y, &q1.x), &f.add(&q2.y, &q2.x));
        let c = f.mul(&f.mul(&q1.t, &self.d2), &q2.t);
        let d = f.mul(&q1.z, &f.add(&q2.z, &q2.z));
        let e = f.sub(&b, &a);
        let g = f.sub(&d, &c);
        let h = f.add(&d, &c);
        let i = f.add(&b, &a);
        ExtendedPoint {
            x: f.mul(&e, &g),
            y: f.mul(&h, &i),
            z: f.mul(&g, &h),
            t: f.mul(&e, &i),
        }
    }

    /// `[scalar]q`, left to right over the bits of the scalar.
    fn scalar_mul(&self, scalar: &BigUint, q: &ExtendedPoint) -> ExtendedPoint {
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
    fn same_point(&self, q1: &ExtendedPoint, q2: &ExtendedPoint) -> bool {
        let f = self.field();
        f.mul(&q1.x, &q2.z) == f.mul(&q2.x, &q1.z) && f.mul(&q1.y, &q2.z) == f.mul(&q2.y, &q1.z)
    }

    /// Whether `[8]q` is the neutral element, i.e. `q` lies in the order-8
    /// subgroup generated by the torsion points rather than in the prime-order
    /// group the base point generates. RFC 8032 section 8.8 discusses the
    /// cofactor; this screen goes further and refuses a public key of small
    /// order outright: under the cofactorless equation `[s]B = R + [k]A`, a
    /// small-order `A` needs no private key at all (for the neutral element
    /// the equation collapses to `[s]B = R`), so refusing such keys removes a
    /// universal-forgery shape rather than relying on the caller never to
    /// supply one. The cofactor of edwards25519 is 8, so three doublings
    /// settle it.
    fn has_small_order(&self, q: &ExtendedPoint) -> bool {
        let q2 = self.add(q, q);
        let q4 = self.add(&q2, &q2);
        let q8 = self.add(&q4, &q4);
        self.same_point(&q8, &self.neutral())
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
        // Only `A` is screened for small order: it is the key the verdict is
        // attributed to, whereas `R` is part of the signature and is judged by
        // the §5.1.7 equation itself.
        if self.has_small_order(&a) {
            return Err(VerifyError::Malformed("EdDSA public key has small order"));
        }
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

/// An edwards448 point in the projective coordinates of RFC 8032 §5.2.4:
/// `x = X/Z` and `y = Y/Z`. There is no `T`: edwards448 is untwisted, so
/// the §5.2.4 addition works from `X`, `Y`, and `Z` alone.
#[derive(Clone)]
struct ProjectivePoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

/// The edwards448 group: the field prime, the curve constant, the order of
/// the base point, and the exponent the square root of §5.2.3 needs
/// (RFC 8032 §5.2).
struct Ed448 {
    /// p = 2^448 - 2^224 - 1.
    p: BigUint,
    /// d = -39081, held as the field element p - 39081. Unlike Ed25519's
    /// it is a small integer, but every use of it is a field
    /// multiplication, so it is stored reduced rather than negated at each
    /// use.
    d: BigUint,
    /// L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885,
    /// the prime order of the base point B.
    l: BigUint,
    /// (p-3)/4, the exponent of the §5.2.3 square-root formula. A constant
    /// rather than a division, since p is a constant too. p is 3 mod 4, so
    /// this one exponent is the whole square root: there is no sqrt(-1)
    /// correction of the kind §5.1.3 needs.
    sqrt_exponent: BigUint,
    /// The base point B of §5.2, whose encoding is
    /// `14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900`.
    /// The coordinates are stored so that no verification pays for a
    /// square root; `the_ed448_base_point_is_the_one_its_encoding_names`
    /// decodes that encoding and checks it lands here.
    base: ProjectivePoint,
}

impl Ed448 {
    fn new() -> Self {
        Self {
            p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            d: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756"),
            l: hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"),
            sqrt_exponent: hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            base: ProjectivePoint {
                x: hex("4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e"),
                y: hex("693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"),
                z: BigUint::one(),
            },
        }
    }

    fn field(&self) -> Field<'_> {
        Field { p: &self.p }
    }

    /// The neutral element, `(0, 1, 1)` in projective coordinates
    /// (RFC 8032 §5.2.4).
    fn neutral(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: BigUint::zero(),
            y: BigUint::one(),
            z: BigUint::one(),
        }
    }

    /// Recover a point from its 57-byte encoding (RFC 8032 §5.2.3): the
    /// first 56 bytes are `y` little-endian and the top bit of the 57th is
    /// the sign of `x`, which is recovered from the curve equation
    /// `x^2 + y^2 = 1 + d*x^2*y^2` as `x = sqrt((y^2 - 1) / (d*y^2 - 1))`.
    fn decode_point(&self, encoded: &[u8; 57]) -> Result<ProjectivePoint, VerifyError> {
        let f = self.field();
        if encoded[56] & 0x7f != 0 {
            // y takes all 448 bits of the first 56 octets, so the low seven
            // bits of the last one carry nothing and are required to be zero.
            return Err(VerifyError::Malformed(
                "Ed448 point encoding is not canonical",
            ));
        }
        let x_is_odd = encoded[56] >> 7 == 1;
        let y = little_endian(&encoded[..56]);
        if y >= self.p {
            return Err(VerifyError::Malformed(
                "Ed448 y coordinate is not a field element",
            ));
        }
        // p is 3 mod 4, so (u/v)^((p+1)/4) is the candidate root, and
        // u^3 * v * (u^5 * v^3)^((p-3)/4) is that value without an
        // inversion (the two exponents differ by p-1).
        let yy = f.sqr(&y);
        let u = f.sub(&yy, &BigUint::one());
        let v = f.sub(&f.mul(&self.d, &yy), &BigUint::one());
        let u2 = f.sqr(&u);
        let u3 = f.mul(&u2, &u);
        let u5 = f.mul(&u3, &u2);
        let v3 = f.mul(&f.sqr(&v), &v);
        let candidate = f.pow(&f.mul(&u5, &v3), &self.sqrt_exponent);
        let mut x = f.mul(&f.mul(&u3, &v), &candidate);
        // v*x^2 == u says the root is genuine. There is no second chance
        // here: if it fails, u/v is a non-residue and this y names no point.
        if f.mul(&v, &f.sqr(&x)) != u {
            return Err(VerifyError::Malformed("Ed448 point is not on the curve"));
        }
        if x.is_zero() && x_is_odd {
            // x = 0 has one encoding, so a set sign bit is not canonical.
            return Err(VerifyError::Malformed(
                "Ed448 point has a non-canonical sign bit",
            ));
        }
        if x.is_odd() != x_is_odd {
            x = f.neg(&x);
        }
        Ok(ProjectivePoint {
            x,
            y,
            z: BigUint::one(),
        })
    }

    /// The addition of RFC 8032 §5.2.4, which is unified on an untwisted
    /// Edwards curve with a non-square `d`, so doubling is just `add(q, q)`.
    fn add(&self, q1: &ProjectivePoint, q2: &ProjectivePoint) -> ProjectivePoint {
        let f = self.field();
        // The RFC names these A, B, C, D, E, F, G, H; `d`, `g`, `h`, and
        // `i` here are its D, F, G, and H, since `f` is the field helper
        // and `e` is already taken by E.
        let a = f.mul(&q1.z, &q2.z);
        let b = f.sqr(&a);
        let c = f.mul(&q1.x, &q2.x);
        let d = f.mul(&q1.y, &q2.y);
        let e = f.mul(&f.mul(&self.d, &c), &d);
        let g = f.sub(&b, &e);
        let h = f.add(&b, &e);
        let i = f.mul(&f.add(&q1.x, &q1.y), &f.add(&q2.x, &q2.y));
        ProjectivePoint {
            x: f.mul(&f.mul(&a, &g), &f.sub(&f.sub(&i, &c), &d)),
            y: f.mul(&f.mul(&a, &h), &f.sub(&d, &c)),
            z: f.mul(&g, &h),
        }
    }

    /// `[scalar]q`, left to right over the bits of the scalar.
    fn scalar_mul(&self, scalar: &BigUint, q: &ProjectivePoint) -> ProjectivePoint {
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
    fn same_point(&self, q1: &ProjectivePoint, q2: &ProjectivePoint) -> bool {
        let f = self.field();
        f.mul(&q1.x, &q2.z) == f.mul(&q2.x, &q1.z) && f.mul(&q1.y, &q2.z) == f.mul(&q2.y, &q1.z)
    }

    /// Whether `[4]q` is the neutral element, the edwards448 counterpart of
    /// the Ed25519 check: RFC 8032 section 8.8 discusses the cofactor; this
    /// screen goes further and refuses a public key of small order outright,
    /// for the reason Ed25519's `has_small_order` gives. The cofactor of
    /// edwards448 is 4, so two doublings settle it.
    fn has_small_order(&self, q: &ProjectivePoint) -> bool {
        let q2 = self.add(q, q);
        let q4 = self.add(&q2, &q2);
        self.same_point(&q4, &self.neutral())
    }

    /// RFC 8032 §5.2.7 step 3, in the cofactorless form the same section
    /// permits: check `[s]B = R + [k]A` rather than its fourfold.
    fn verify(&self, public_key: &[u8], r: &[u8], s: &[u8], k: &[u8]) -> Result<bool, VerifyError> {
        let encoded_a: &[u8; 57] = public_key
            .try_into()
            .map_err(|_| VerifyError::Malformed("Ed448 public key length"))?;
        let encoded_r: &[u8; 57] = r
            .try_into()
            .map_err(|_| VerifyError::Malformed("Ed448 signature length"))?;
        if s.len() != 57 {
            return Err(VerifyError::Malformed("Ed448 signature length"));
        }
        if k.len() != 114 {
            return Err(VerifyError::Malformed("Ed448 challenge length"));
        }
        let a = self.decode_point(encoded_a)?;
        // Only `A` is screened for small order, for the reason Ed25519's
        // `verify` gives: `R` is signature material, not a key.
        if self.has_small_order(&a) {
            return Err(VerifyError::Malformed("EdDSA public key has small order"));
        }
        let big_r = self.decode_point(encoded_r)?;
        // s must be the canonical little-endian encoding of a scalar below
        // the group order; anything larger is a malleable re-encoding of
        // some other signature and is simply wrong, not malformed. L is
        // under 2^446, so this also covers §5.2.7's requirement that the
        // 57th octet of s be zero.
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
    fn a_small_order_public_key_is_malformed() {
        // The neutral element (0, 1): y = 1 little-endian with the x sign bit
        // clear. It has order 1, so the small-order screen (RFC 8032 section
        // 8.8 discusses the cofactor; this screen goes further and refuses a
        // public key of small order outright) rejects it before the
        // signature equation is reached.
        let mut key = vec![0u8; 32];
        key[0] = 1;
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
            Err(VerifyError::Malformed("EdDSA public key has small order"))
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

    /// One RFC 8032 §7.4 vector: public key, signature, and the challenge
    /// `SHAKE256(dom4(0, "") || R || A || M, 114)` computed from them with
    /// `hashlib`.
    struct Ed448Vector {
        public_key: &'static str,
        signature: &'static str,
        challenge: &'static str,
    }

    /// RFC 8032 §7.4 "Blank" (empty message).
    const ED448_BLANK: Ed448Vector = Ed448Vector {
        public_key: "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        signature: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
        challenge: "6d0fb27a6c0e46ca6b0789469bdfc1143d07fb1d3f68c57de3acc87375b1955b97cfb23c4472756f9240a32b8569a3676cf0355afc8fa26875f3161a9ed2a6b69ce5753eb8925d71cc660b22e94282dab9b580f21b6860f5b209abe22489346de785dd0734dee55bbf712feb902947f906c4",
    };

    /// RFC 8032 §7.4 "1 octet" (the message `03`).
    const ED448_ONE_OCTET: Ed448Vector = Ed448Vector {
        public_key: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        signature: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
        challenge: "a1e2cb4e8b7dd00631d36979c28c729b5dfed35ed27ba5c351ea2ec9fbfec332e6f091cf2e1453d9c9536a2b5b96ee16bbba8b52d597b817f1d949834a77046d5e04442877d8c18ff7067ab08e9bbb57013a19555d8227967206ffd4e18ccfc753bc1fb19a07f8a2003019b3ae911634a49f",
    };

    /// RFC 8032 §7.4 "1023 octets". The message is a kilobyte, so only its
    /// challenge is quoted here; the key and signature are the ones
    /// `tests/fixtures/wycheproof/ed448_test.json` carries for tcId 86,
    /// whose comment names this same RFC vector.
    const ED448_1023_OCTETS: Ed448Vector = Ed448Vector {
        public_key: "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
        signature: "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00",
        challenge: "7705a337a3f558ca1c8617490f7128fbfc87fcb83604701064d22fde15b82273ec8e64e1c261a3144918b7bf8708ccd4ff24b188ef3fc4e3beeb3c48e8c5feeab0ef24da68d2306fd67ef569b85725f4215bd5aa9d566ba982a7a07fa2cd5c71f03e8e4f43575e6681e08636800ffb8b2a95",
    };

    fn check_ed448(vector: &Ed448Vector) -> Result<bool, VerifyError> {
        let key = hex_bytes(vector.public_key);
        let signature = hex_bytes(vector.signature);
        let challenge = hex_bytes(vector.challenge);
        verify(
            EdCurve::Ed448,
            &key,
            &signature[..57],
            &signature[57..],
            &challenge,
        )
    }

    #[test]
    fn rfc8032_ed448_vectors_verify() {
        for vector in [&ED448_BLANK, &ED448_ONE_OCTET, &ED448_1023_OCTETS] {
            assert_eq!(check_ed448(vector), Ok(true), "{}", vector.public_key);
        }
    }

    #[test]
    fn the_ed448_base_point_is_the_one_its_encoding_names() {
        // RFC 8032 §5.2 publishes B both as coordinates and as the encoding
        // below; `Ed448::new` stores the coordinates, so decoding the
        // encoding here is what ties the two together.
        let curve = Ed448::new();
        let encoded = hex_bytes(
            "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        );
        let decoded = curve
            .decode_point(encoded[..].try_into().expect("57 bytes"))
            .expect("the base point decodes");
        assert!(curve.same_point(&decoded, &curve.base));
    }

    #[test]
    fn a_different_ed448_challenge_does_not_verify() {
        let key = hex_bytes(ED448_BLANK.public_key);
        let signature = hex_bytes(ED448_BLANK.signature);
        let mut challenge = hex_bytes(ED448_BLANK.challenge);
        challenge[7] ^= 1;
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Ok(false)
        );
    }

    #[test]
    fn an_ed448_scalar_at_or_above_the_group_order_does_not_verify() {
        // RFC 8032 §5.2.7 requires s < L, and L itself is the smallest
        // non-canonical encoding.
        let key = hex_bytes(ED448_BLANK.public_key);
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        let order = hex_bytes("f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00");
        assert_eq!(
            verify(EdCurve::Ed448, &key, &signature[..57], &order, &challenge),
            Ok(false)
        );
    }

    #[test]
    fn an_ed448_public_key_whose_y_is_not_a_field_element_is_malformed() {
        // y = 2^448 - 1, above p = 2^448 - 2^224 - 1.
        let mut key = vec![0xff; 57];
        key[56] = 0;
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed(
                "Ed448 y coordinate is not a field element"
            ))
        );
    }

    #[test]
    fn an_ed448_point_off_the_curve_is_malformed() {
        // y = 2 has no matching x on edwards448 either.
        let mut key = vec![0u8; 57];
        key[0] = 2;
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed448 point is not on the curve"))
        );
    }

    #[test]
    fn a_small_order_ed448_public_key_is_malformed() {
        // The 57-byte encoding of the neutral element (0, 1): y = 1
        // little-endian across the first 56 octets, x sign bit clear in the
        // 57th. Order 1, so the small-order screen (RFC 8032 section 8.8
        // discusses the cofactor; this screen goes further and refuses a
        // public key of small order outright) rejects it here too.
        let mut key = vec![0u8; 57];
        key[0] = 1;
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed("EdDSA public key has small order"))
        );
    }

    #[test]
    fn an_ed448_high_byte_that_is_not_just_a_sign_bit_is_malformed() {
        // RFC 8032 §5.2.2 spends all of y on the first 56 octets, so the
        // low seven bits of the 57th carry nothing and must be zero.
        let mut key = hex_bytes(ED448_BLANK.public_key);
        key[56] |= 1;
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed(
                "Ed448 point encoding is not canonical"
            ))
        );
    }

    #[test]
    fn wrong_ed448_lengths_are_malformed() {
        let key = hex_bytes(ED448_BLANK.public_key);
        let signature = hex_bytes(ED448_BLANK.signature);
        let challenge = hex_bytes(ED448_BLANK.challenge);
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key[..56],
                &signature[..57],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed448 public key length"))
        );
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..56],
                &signature[57..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed448 signature length"))
        );
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[58..],
                &challenge,
            ),
            Err(VerifyError::Malformed("Ed448 signature length"))
        );
        assert_eq!(
            verify(
                EdCurve::Ed448,
                &key,
                &signature[..57],
                &signature[57..],
                &challenge[..113],
            ),
            Err(VerifyError::Malformed("Ed448 challenge length"))
        );
    }
}
