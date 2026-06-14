// fuzz/fuzz_targets/parse_server_hello.rs
//
// Fuzz the TLS ServerHello / HelloRetryRequest parser. This is the
// parser the PQ probe (#33) feeds with bytes received from arbitrary
// remote servers, so the "never panics on adversarial input" guarantee
// matters as much here as for the certificate parser. Also exercises
// the record deframer with the same input for free.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic; errors are fine.
    let _ = certinfo::tls::handshake::parse_server_hello(data);
    let _ = certinfo::tls::records::read_record(data);
});
