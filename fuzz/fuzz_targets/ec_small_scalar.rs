// fuzz/fuzz_targets/ec_small_scalar.rs
//
// Fuzz the weak EC key search: SubjectPublicKeyInfo parsing, the SEC 1
// point decoder and on-curve check, and the point addition loop. The first
// byte picks a mode; the rest is fed as a whole key, or as a raw point
// wrapped in a well-formed P-256, P-384, or P-521 key so the input gets
// past the outer DER. The bound stays small to keep throughput up. Any
// `Ok` or `Err` is fine; a panic is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

// AlgorithmIdentifier { id-ecPublicKey, namedCurve } for each curve.
const P256_ALGORITHM: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
const P384_ALGORITHM: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
    0x04, 0x00, 0x22,
];
const P521_ALGORITHM: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
    0x04, 0x00, 0x23,
];

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(body);
    out
}

fn wrap_point(algorithm: &[u8], point: &[u8]) -> Vec<u8> {
    let bits = [&[0u8][..], point].concat();
    tlv(0x30, &[algorithm, &tlv(0x03, &bits)].concat())
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let bound = u64::from(mode >> 2);
    let spki = match mode % 4 {
        0 => rest.to_vec(),
        1 => wrap_point(P256_ALGORITHM, rest),
        2 => wrap_point(P384_ALGORITHM, rest),
        _ => wrap_point(P521_ALGORITHM, rest),
    };
    let _ = certinfo::ec_small_scalar(&spki, bound);
});
