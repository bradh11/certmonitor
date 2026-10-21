// rust_certinfo/src/crypto/ecdsa/small_multiples.rs
//
// A precomputed table of [k]G for k in 1..=TABLE_LEN on each curve, so
// `small_scalar` can answer for the common bound with one lookup instead of
// thousands of point additions. Each entry is the low 8 bytes of the affine
// x coordinate followed by k, both big-endian, sorted by those 8 bytes.
// `scripts/generate_small_multiples.py` writes the files with its own
// arithmetic; the test below recomputes every entry with this crate's.

use super::Curve;
use crate::crypto::bigint::BigUint;

pub const TABLE_LEN: u64 = 4096;
const ENTRY: usize = 10;

fn table(curve: Curve) -> &'static [u8] {
    match curve {
        Curve::P256 => include_bytes!("small_multiples/p256.bin"),
        Curve::P384 => include_bytes!("small_multiples/p384.bin"),
        Curve::P521 => include_bytes!("small_multiples/p521.bin"),
    }
}

/// The `k` whose `[k]G` has the same low 8 bytes of x as `x`, if any. A
/// hit is a candidate: the caller confirms it with a full multiplication.
pub fn lookup(curve: Curve, x: &BigUint) -> Option<u64> {
    let bytes = x.to_be_bytes(curve.params().size)?;
    let low: [u8; 8] = bytes[bytes.len() - 8..].try_into().ok()?;
    let (entries, _) = table(curve).as_chunks::<ENTRY>();
    let index = entries
        .binary_search_by(|entry| entry[..8].cmp(&low))
        .ok()?;
    Some(u64::from(u16::from_be_bytes([
        entries[index][8],
        entries[index][9],
    ])))
}

#[cfg(test)]
mod tests {
    use super::super::{Field, Point};
    use super::*;

    #[test]
    fn each_table_holds_one_sorted_entry_per_multiple() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let (entries, rest) = table(curve).as_chunks::<ENTRY>();
            assert_eq!(
                (entries.len(), rest.len()),
                (TABLE_LEN as usize, 0),
                "{curve:?}"
            );
            assert!(
                entries.windows(2).all(|w| w[0][..8] < w[1][..8]),
                "{curve:?}"
            );
        }
    }

    #[test]
    fn every_small_multiple_of_the_generator_is_found() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let params = curve.params();
            let field = Field { p: &params.p };
            let g = Point {
                x: params.gx.clone(),
                y: params.gy.clone(),
                z: BigUint::one(),
            };
            let mut multiples = vec![g.clone()];
            for _ in 1..TABLE_LEN {
                let next = field.add_points(multiples.last().unwrap(), &g);
                multiples.push(next);
            }
            // Montgomery's trick: invert every Z with one inversion, since a
            // debug build spends over a minute doing 12288 of them one by one.
            let mut prefix = vec![BigUint::one()];
            for point in &multiples {
                let next = field.mul(prefix.last().unwrap(), &point.z);
                prefix.push(next);
            }
            let mut inverse = field.inv(prefix.last().unwrap());
            for index in (0..multiples.len()).rev() {
                let zinv = field.mul(&inverse, &prefix[index]);
                inverse = field.mul(&inverse, &multiples[index].z);
                let x = field.mul(&multiples[index].x, &field.sqr(&zinv));
                let k = index as u64 + 1;
                assert_eq!(lookup(curve, &x), Some(k), "{curve:?} k={k}");
            }
        }
    }

    #[test]
    fn an_x_that_is_not_a_small_multiple_is_not_found() {
        assert_eq!(lookup(Curve::P384, &BigUint::from_u64(12345)), None);
    }
}
