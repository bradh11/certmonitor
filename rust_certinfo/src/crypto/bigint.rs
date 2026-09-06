// rust_certinfo/src/crypto/bigint.rs
//
// Just enough unsigned big-integer arithmetic to verify signatures:
// comparison, addition, subtraction, schoolbook multiplication, Knuth's
// algorithm D for division, and square-and-multiply modular power. Limbs
// are little-endian u32 so every intermediate fits a u64. Values are kept
// normalized (no high zero limbs) so comparisons are by length first.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn from_u64(value: u64) -> Self {
        let mut n = Self {
            limbs: vec![value as u32, (value >> 32) as u32],
        };
        n.normalize();
        n
    }

    /// Decode the value bytes of a DER INTEGER that must be positive and
    /// canonically encoded: non-empty, no sign bit, and a leading zero only
    /// when the next byte needs it. Anything else is `None`.
    pub fn from_der_positive(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [] => None,
            [first, ..] if first & 0x80 != 0 => None,
            [0, second, ..] if second & 0x80 == 0 => None,
            _ => Some(Self::from_be_bytes(bytes)),
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(4));
        for chunk in bytes.rchunks(4) {
            let mut limb = 0u32;
            for byte in chunk {
                limb = (limb << 8) | u32::from(*byte);
            }
            limbs.push(limb);
        }
        let mut n = Self { limbs };
        n.normalize();
        n
    }

    /// Big-endian bytes, left-padded with zeros to `width` bytes. Returns
    /// `None` if the value does not fit.
    pub fn to_be_bytes(&self, width: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; width];
        let mut index = width;
        for limb in &self.limbs {
            for shift in [0, 8, 16, 24] {
                let byte = (limb >> shift) as u8;
                if index == 0 {
                    if byte != 0 {
                        return None;
                    }
                    continue;
                }
                index -= 1;
                out[index] = byte;
            }
        }
        Some(out)
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }

    pub fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    pub fn bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / 32)
            .is_some_and(|limb| (limb >> (index % 32)) & 1 == 1)
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        let (long, short) = if self.limbs.len() >= other.limbs.len() {
            (self, other)
        } else {
            (other, self)
        };
        let mut limbs = Vec::with_capacity(long.limbs.len() + 1);
        let mut carry = 0u64;
        for (i, limb) in long.limbs.iter().enumerate() {
            let sum = u64::from(*limb) + u64::from(*short.limbs.get(i).unwrap_or(&0)) + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            limbs.push(carry as u32);
        }
        Self { limbs }
    }

    /// `self - other`; the caller guarantees `self >= other`.
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert!(self.cmp(other) != Ordering::Less);
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for (i, limb) in self.limbs.iter().enumerate() {
            let mut diff = i64::from(*limb) - i64::from(*other.limbs.get(i).unwrap_or(&0)) - borrow;
            if diff < 0 {
                diff += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            limbs.push(diff as u32);
        }
        let mut n = Self { limbs };
        n.normalize();
        n
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, b) in other.limbs.iter().enumerate() {
                let current = u64::from(limbs[i + j]) + u64::from(*a) * u64::from(*b) + carry;
                limbs[i + j] = current as u32;
                carry = current >> 32;
            }
            let mut k = i + other.limbs.len();
            while carry != 0 {
                let current = u64::from(limbs[k]) + carry;
                limbs[k] = current as u32;
                carry = current >> 32;
                k += 1;
            }
        }
        let mut n = Self { limbs };
        n.normalize();
        n
    }

    fn shl_bits(&self, bits: u32) -> Self {
        if bits == 0 {
            return self.clone();
        }
        let mut limbs = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u32;
        for limb in &self.limbs {
            limbs.push((limb << bits) | carry);
            carry = limb >> (32 - bits);
        }
        if carry != 0 {
            limbs.push(carry);
        }
        Self { limbs }
    }

    fn shr_bits(&self, bits: u32) -> Self {
        if bits == 0 {
            return self.clone();
        }
        let mut limbs = vec![0u32; self.limbs.len()];
        for i in 0..self.limbs.len() {
            let high = self.limbs.get(i + 1).copied().unwrap_or(0);
            limbs[i] = (self.limbs[i] >> bits) | (high << (32 - bits));
        }
        let mut n = Self { limbs };
        n.normalize();
        n
    }

    /// Quotient and remainder of `self / divisor` (Knuth, TAOCP 4.3.1 D).
    /// The caller guarantees `divisor` is non-zero.
    pub fn divrem(&self, divisor: &Self) -> (Self, Self) {
        debug_assert!(!divisor.is_zero());
        if self.cmp(divisor) == Ordering::Less {
            return (Self::zero(), self.clone());
        }
        if divisor.limbs.len() == 1 {
            let d = u64::from(divisor.limbs[0]);
            let mut quotient = vec![0u32; self.limbs.len()];
            let mut rem = 0u64;
            for i in (0..self.limbs.len()).rev() {
                let current = (rem << 32) | u64::from(self.limbs[i]);
                quotient[i] = (current / d) as u32;
                rem = current % d;
            }
            let mut q = Self { limbs: quotient };
            q.normalize();
            return (q, Self::from_u64(rem));
        }

        // Normalize so the divisor's top limb has its high bit set.
        let shift = divisor.limbs.last().unwrap().leading_zeros();
        let v = divisor.shl_bits(shift);
        let mut u = self.shl_bits(shift).limbs;
        u.push(0);
        let n = v.limbs.len();
        let m = u.len() - n - 1;
        let v_top = u64::from(v.limbs[n - 1]);
        let v_next = u64::from(v.limbs[n - 2]);
        let mut quotient = vec![0u32; m + 1];

        for j in (0..=m).rev() {
            let numerator = (u64::from(u[j + n]) << 32) | u64::from(u[j + n - 1]);
            let mut qhat = numerator / v_top;
            let mut rhat = numerator % v_top;
            while qhat >= (1 << 32) || qhat * v_next > ((rhat << 32) | u64::from(u[j + n - 2])) {
                qhat -= 1;
                rhat += v_top;
                if rhat >= (1 << 32) {
                    break;
                }
            }
            // Multiply and subtract qhat * v from u[j..j+n+1].
            let mut borrow = 0i64;
            let mut carry = 0u64;
            for i in 0..n {
                let product = qhat * u64::from(v.limbs[i]) + carry;
                carry = product >> 32;
                let diff = i64::from(u[i + j]) - i64::from(product as u32) - borrow;
                if diff < 0 {
                    u[i + j] = (diff + (1 << 32)) as u32;
                    borrow = 1;
                } else {
                    u[i + j] = diff as u32;
                    borrow = 0;
                }
            }
            let diff = i64::from(u[j + n]) - carry as i64 - borrow;
            if diff < 0 {
                // qhat was one too large: add v back.
                u[j + n] = (diff + (1 << 32)) as u32;
                qhat -= 1;
                let mut carry = 0u64;
                for i in 0..n {
                    let sum = u64::from(u[i + j]) + u64::from(v.limbs[i]) + carry;
                    u[i + j] = sum as u32;
                    carry = sum >> 32;
                }
                u[j + n] = u[j + n].wrapping_add(carry as u32);
            } else {
                u[j + n] = diff as u32;
            }
            quotient[j] = qhat as u32;
        }
        let mut q = Self { limbs: quotient };
        q.normalize();
        u.truncate(n);
        let mut r = Self { limbs: u };
        r.normalize();
        (q, r.shr_bits(shift))
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        self.divrem(modulus).1
    }

    /// `self ^ exponent mod modulus`; `modulus` must be non-zero.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        let mut result = Self::one().rem(modulus);
        let base = self.rem(modulus);
        for i in (0..exponent.bit_len()).rev() {
            result = result.mul(&result).rem(modulus);
            if exponent.bit(i) {
                result = result.mul(&base).rem(modulus);
            }
        }
        result
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a.cmp(b);
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> BigUint {
        let mut digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if digits.len() % 2 == 1 {
            digits.insert(0, '0');
        }
        let bytes: Vec<u8> = (0..digits.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
            .collect();
        BigUint::from_be_bytes(&bytes)
    }

    #[test]
    fn small_arithmetic_matches_u128() {
        let a = 0xfedc_ba98_7654_3210_u64;
        let b = 0x0f0f_0f0f_1234_5678_u64;
        let (big_a, big_b) = (BigUint::from_u64(a), BigUint::from_u64(b));
        let product = u128::from(a) * u128::from(b);
        assert_eq!(big_a.mul(&big_b), hex(&format!("{product:x}")));
        assert_eq!(
            big_a.add(&big_b),
            hex(&format!("{:x}", u128::from(a) + u128::from(b)))
        );
        assert_eq!(big_a.sub(&big_b), BigUint::from_u64(a - b));
        let (q, r) = big_a.divrem(&big_b);
        assert_eq!(q, BigUint::from_u64(a / b));
        assert_eq!(r, BigUint::from_u64(a % b));
    }

    #[test]
    fn division_with_multi_limb_divisor_and_add_back() {
        // Chosen so Knuth's qhat estimate overshoots and the add-back runs.
        let dividend = hex("7fffffff800000010000000000000000");
        let divisor = hex("800000008000000200000005");
        let (q, r) = dividend.divrem(&divisor);
        assert_eq!(q.mul(&divisor).add(&r), dividend);
        assert!(r < divisor);
        let dividend = hex("ffffffffffffffffffffffffffffffffffffffffffffffff");
        let divisor = hex("100000000000000000000001");
        let (q, r) = dividend.divrem(&divisor);
        assert_eq!(q.mul(&divisor).add(&r), dividend);
        assert!(r < divisor);
    }

    #[test]
    fn mod_pow_matches_python() {
        // pow(0x1234567890abcdef, 65537, 0xfffffffffffffffffffffffffffffffeffffffffffffffff)
        let base = hex("1234567890abcdef");
        let exponent = BigUint::from_u64(65537);
        let modulus = hex("fffffffffffffffffffffffffffffffeffffffffffffffff");
        assert_eq!(
            base.mod_pow(&exponent, &modulus),
            hex("46a590e0bf2faa2ffa624503f30cb8b4462d8df1739895ec")
        );
        assert_eq!(
            hex("05").mod_pow(&BigUint::zero(), &hex("07")),
            BigUint::one()
        );
    }

    #[test]
    fn byte_round_trips_and_bits() {
        let n = hex("00ff00ff00ff00ff00ff");
        assert_eq!(
            n.to_be_bytes(10).unwrap(),
            hex_bytes("00ff00ff00ff00ff00ff")
        );
        assert_eq!(n.to_be_bytes(9).unwrap(), hex_bytes("ff00ff00ff00ff00ff"));
        assert!(n.to_be_bytes(8).is_none());
        assert_eq!(n.bit_len(), 72);
        assert!(n.bit(0) && !n.bit(8) && n.bit(71));
        assert!(BigUint::zero().to_be_bytes(0).unwrap().is_empty());
        assert!(!BigUint::zero().is_odd() && hex("03").is_odd());
    }

    #[test]
    fn der_integers_must_be_canonical_and_positive() {
        assert_eq!(
            BigUint::from_der_positive(&[0x7f]),
            Some(BigUint::from_u64(0x7f))
        );
        assert_eq!(
            BigUint::from_der_positive(&[0x00, 0x80]),
            Some(BigUint::from_u64(0x80))
        );
        assert_eq!(BigUint::from_der_positive(&[0x00]), Some(BigUint::zero()));
        assert!(BigUint::from_der_positive(&[]).is_none());
        assert!(BigUint::from_der_positive(&[0x80]).is_none(), "negative");
        assert!(
            BigUint::from_der_positive(&[0x00, 0x7f]).is_none(),
            "non-minimal"
        );
        assert!(
            BigUint::from_der_positive(&[0x00, 0x00, 0x80]).is_none(),
            "non-minimal"
        );
    }

    /// splitmix64, so the property tests are random but reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn big(&mut self, max_bytes: usize) -> BigUint {
            let len = (self.next() as usize) % (max_bytes + 1);
            let bytes: Vec<u8> = (0..len).map(|_| self.next() as u8).collect();
            BigUint::from_be_bytes(&bytes)
        }
    }

    #[test]
    fn division_invariants_hold_on_random_inputs() {
        let mut rng = Rng(0x5eed);
        for _ in 0..3000 {
            let n = rng.big(256);
            let mut d = rng.big(128);
            if d.is_zero() {
                d = BigUint::one();
            }
            let (q, r) = n.divrem(&d);
            assert!(r < d, "remainder must be below the divisor");
            assert_eq!(q.mul(&d).add(&r), n, "q*d + r must rebuild n");
            let (q2, r2) = n.mul(&d).add(&r).divrem(&d);
            assert_eq!((q2, r2), (n.clone(), r), "(n*d + r) / d must give n back");
        }
    }

    #[test]
    fn ring_laws_hold_on_random_inputs() {
        let mut rng = Rng(0xabc);
        for _ in 0..2000 {
            let (a, b, c) = (rng.big(96), rng.big(96), rng.big(96));
            assert_eq!(a.mul(&b), b.mul(&a));
            assert_eq!(a.add(&b), b.add(&a));
            assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
            assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
            assert_eq!(a.add(&b).sub(&b), a);
            let width = a
                .to_be_bytes(0)
                .map(|_| 0)
                .unwrap_or(a.bit_len().div_ceil(8));
            assert_eq!(BigUint::from_be_bytes(&a.to_be_bytes(width).unwrap()), a);
        }
    }

    #[test]
    fn mod_pow_matches_repeated_multiplication_and_fermat() {
        let mut rng = Rng(0xf00d);
        for _ in 0..300 {
            let base = rng.big(64);
            let mut modulus = rng.big(64);
            if modulus.is_zero() {
                modulus = BigUint::from_u64(97);
            }
            let exponent = (rng.next() % 40) as usize;
            let mut expected = BigUint::one().rem(&modulus);
            for _ in 0..exponent {
                expected = expected.mul(&base).rem(&modulus);
            }
            assert_eq!(
                base.mod_pow(&BigUint::from_u64(exponent as u64), &modulus),
                expected
            );
        }
        // Fermat's little theorem with the (prime) P-256 group order.
        let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let n_minus_one = n.sub(&BigUint::one());
        for _ in 0..50 {
            let mut a = rng.big(32).rem(&n);
            if a.is_zero() {
                a = BigUint::from_u64(2);
            }
            assert_eq!(a.mod_pow(&n_minus_one, &n), BigUint::one());
        }
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
