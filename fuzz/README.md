# certinfo fuzzing

`cargo fuzz` target for the in-tree X.509 parser. Validates that
`Certificate::from_der` never panics on arbitrary input. This is a
**manual pre-release gate**, not a CI check — `cargo fuzz` requires the
nightly Rust toolchain and runs for arbitrary durations.

## How it works

The fuzz crate (`fuzz/`) depends on `certinfo` with `default-features =
false`, which disables the `python` feature and drops the entire PyO3
layer. What's left is the pure-Rust DER / X.509 parser core under
`rust_certinfo/src/{der,x509}/` plus `error.rs` — exactly the code we
want to fuzz. No Python interpreter is needed; the fuzz binary runs as
a standalone executable.

This means **the wheel build is unaffected**. `make develop`, the
release wheel, and `cargo test` of the main crate all build with the
default `python` feature on and get the full PyO3 surface.

## Why fuzz the parser

The new in-tree DER parser takes untrusted bytes from the network on
every TLS handshake. The risk classes fuzzing defends against:

1. **Panic on malformed input.** `#![forbid(unsafe_code)]` at the
   certinfo crate root prevents memory-safety bugs, but Rust panics
   still abort the process. Every bounds-check in the parser is a
   potential panic if I got the math wrong. Fuzzing tries millions of
   adversarial byte sequences and reports any that crash.
2. **Pathological CPU on malformed input** (denial of service). A
   length-parsing bug that loops on a particular byte sequence is the
   kind of thing only a coverage-guided fuzzer reliably finds.
3. **Bounds bugs in length fields.** Historically the #1 source of CVEs
   in DER/ASN.1 parsers. Hand-written tests cover the cases I thought
   of; libfuzzer covers the cases I didn't.

Existing tests in `tests/test_certinfo_corpus.py` already run every
public certinfo entry point against 130 real-world certs on every CI
run. Fuzzing is the deeper, slower defense against the bytes a real
cert never contains. **It's worth running before tagging a release**;
not worth running on every commit.

## Easy mode (recommended)

From the repo root:

```sh
make fuzz           # 60-second smoke run
make fuzz-long      # 1-hour soak run
```

`make fuzz` handles toolchain checks (nightly, cargo-fuzz), seeds the
corpus from `tests/fixtures/diff_corpus/`, and runs the parser fuzz
target. Acceptance: zero crashes during the run.

## Manual run

If you want to run for a specific duration or with custom libfuzzer
flags:

```sh
rustup toolchain install nightly        # one-time
cargo install cargo-fuzz                # one-time

cargo +nightly fuzz run parse_certificate -- -max_total_time=3600
```

Drop `-max_total_time` to run until you Ctrl-C. Crashes (if any) land
under `fuzz/artifacts/parse_certificate/` — each file is
the exact byte sequence that triggered the crash, ready to drop into a
unit test for regression coverage.

## Pre-release gate

Before tagging a release that touches `rust_certinfo/src/{der,x509}/`:

1. Run `make fuzz-long` (1 hour minimum). Longer is better — 4 hours
   is a reasonable soak.
2. Verify zero entries in `fuzz/artifacts/`.
3. Note the `#runs` and `cov` numbers from the libfuzzer output in
   the release notes so future maintainers can see the gate was
   honored.

## Why this is not in CI

`cargo fuzz` needs nightly Rust, takes orders of magnitude longer than
a unit test, and brings in `libfuzzer-sys`. None of those belong in PR
CI. The corpus snapshot test at `tests/test_certinfo_corpus.py` covers
the day-to-day regression check against real-world certs; this fuzz
target is the deeper, slower defense against malformed input we
haven't seen yet.

## Adding new fuzz targets

To fuzz another entry point (e.g. `analyze_chain`), add a new file
under `fuzz_targets/` and a matching `[[bin]]` block in `Cargo.toml`.
The DER reader, OID decoder, and time decoders are good candidates for
isolated targets if you want narrower fuzzing of specific layers.
