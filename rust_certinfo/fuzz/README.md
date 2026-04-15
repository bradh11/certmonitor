# certinfo fuzzing

`cargo fuzz` target for the in-tree X.509 parser. Validates that
`Certificate::from_der` never panics on arbitrary input. This is a
**manual pre-merge gate**, not a CI check — `cargo fuzz` requires the
nightly Rust toolchain and runs for arbitrary durations.

## When to run

- Before merging any PR that touches `rust_certinfo/src/der/` or
  `rust_certinfo/src/x509/`.
- Before any release tag.

## Setup (one-time)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Run

```sh
cd rust_certinfo
cargo +nightly fuzz run parse_certificate -- -max_total_time=3600
```

That's a 1-hour run. Use a longer `-max_total_time` (in seconds) for a
deeper soak. The seed corpus is auto-discovered from
`rust_certinfo/fuzz/corpus/parse_certificate/` if present; you can seed
it once with the captured chain corpus:

```sh
mkdir -p rust_certinfo/fuzz/corpus/parse_certificate
cp tests/fixtures/diff_corpus/*.der rust_certinfo/fuzz/corpus/parse_certificate/
```

## Acceptance gate

- **Zero crashes** during the run. Any crash is a release blocker.
- The fuzzer's `coverage` and `cov` counters should reach a stable
  plateau before the timeout — if they're still climbing rapidly when
  the run ends, extend `-max_total_time`.
- Note the `#runs` and `cov` numbers in the PR description so future
  reviewers can see the gate was honored.

## Why this is not in CI

`cargo fuzz` needs nightly Rust, takes orders of magnitude longer than a
unit test, and pulls in `libfuzzer-sys`. None of those belong in the
PR-time CI matrix. The corpus snapshot test in
`tests/test_certinfo_corpus.py` covers the day-to-day regression check
against real-world certs; this fuzz target is the deeper, slower
defense against malformed input we haven't seen yet.
