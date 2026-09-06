// fuzz/fuzz_targets/verify_signature.rs
//
// Fuzz the signature verifier: DER parsing of signatures and keys, the
// big-integer arithmetic behind RSA and ECDSA, and the algorithm dispatch.
// The first byte picks a mode; the rest is fed as the signature against a
// fixed real key, or as the public key against a fixed signature. Any
// `Ok(false)` or `Err` is fine; a panic is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

const RSA_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b9e8554638794b3d1c8513d1881af18518c7a05e9430788ba3e9290512d0f307e3c9b50c9508e4c525186ff53d2ddd6faf49c5fef2cdd6168ae6c4113a106995626a920c742588e71fd1fb766fb1d5ca746150119af4a4696a043c1beced3e8beb6c8ae4aa29e2cc33585001a1b34e1049e22bc60c3e73ad81c0043fb83e4ccb60e0d25278e2cc4c2d97e3d35a27638d7a94e602165c05124d4c78594f1ce6183bffab6b22b4f46dc2ffb46b490303534bd6099b269bede4838009b7d1892222b43e25cd5fc101765bb0c076ff37501777340ce56aee5312780bad93009133915a85f307f41569ebf212d724163172569bc6af94ac02af5d76a8cd87cbd0c4b30203010001";
const P256_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200044f016b88c8d927ccbbc2aa526d6d96ed5e1666f8f5197f8f0bb65416650c1ef247d072c4d823c9a31346a78c0781c3f1a234a30cf8747346f11bb51aed1ec814";
const P256_SIG: &str = "304502200887dee88830dcff1f841a6630d586439552ea472484f8344932b3689cebab77022100fc371ce8beb4faba7a6da49d9b20cfa2a5ecda987106ac0dee41b3a2ebe92c47";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let digest32 = [0x5au8; 32];
    match mode % 4 {
        // Arbitrary bytes as an RSA signature.
        0 => {
            let _ = certinfo::verify_signature("1.2.840.113549.1.1.11", &digest32, rest, &hex(RSA_SPKI));
        }
        // Arbitrary bytes as an ECDSA signature.
        1 => {
            let _ = certinfo::verify_signature("1.2.840.10045.4.3.2", &digest32, rest, &hex(P256_SPKI));
        }
        // Arbitrary bytes as an RSA public key.
        2 => {
            let _ = certinfo::verify_signature("1.2.840.113549.1.1.11", &digest32, &[0u8; 256], rest);
        }
        // Arbitrary bytes as an EC public key against a real signature.
        _ => {
            let _ = certinfo::verify_signature("1.2.840.10045.4.3.2", &digest32, &hex(P256_SIG), rest);
        }
    }
});
