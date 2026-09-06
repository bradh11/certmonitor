// fuzz/fuzz_targets/bigint_divrem.rs
//
// Fuzz the big-integer arithmetic with an oracle: split the input into a
// dividend and a divisor and check the division identity `q * d + r == n`
// with `r < d`, then a modular power against repeated multiplication.
// Unlike the parser targets, the assertions here are the point: a failed
// assertion is a wrong answer, which for signature verification means a
// wrong verdict.

#![no_main]

use certinfo::BigUint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = 1 + (data[0] as usize) % (data.len() - 1);
    let n = BigUint::from_be_bytes(&data[1..split]);
    let d = BigUint::from_be_bytes(&data[split..]);
    if d.is_zero() {
        return;
    }
    let (q, r) = n.divrem(&d);
    assert!(r < d, "remainder not below divisor");
    assert_eq!(q.mul(&d).add(&r), n, "division identity violated");

    let exponent = (data[0] % 16) as u64;
    let mut expected = BigUint::one().rem(&d);
    for _ in 0..exponent {
        expected = expected.mul(&n).rem(&d);
    }
    assert_eq!(n.mod_pow(&BigUint::from_u64(exponent), &d), expected, "mod_pow mismatch");
});
