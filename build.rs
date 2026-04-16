// build.rs
//
// Emit platform-specific linker flags so `cargo test` and `cargo clippy
// --all-targets` can successfully link test binaries that depend on the
// `certinfo` crate on macOS. This is independent of the `cdylib` build
// (which maturin uses to produce the Python wheel) — pyo3's own build
// script handles the cdylib link via `cargo:rustc-cdylib-link-arg`.
// The wheel has always built fine. The issue was specifically with
// test binaries (which are `bin` targets), where the cdylib-scoped
// directives don't apply, so the linker tries to resolve Python
// symbols from libpyo3.rlib at test-binary link time.
//
// The fix: emit `cargo:rustc-link-arg=...` at the certinfo crate level
// so the flags apply to every linked target in the crate (cdylib, test
// binaries, integration tests, examples). Only needed on macOS; Linux
// allows undefined symbols in shared/executable targets by default,
// and Windows has its own pyo3 import-lib machinery.
//
// Without this file, adding `rlib` to `crate-type` breaks
// `cargo clippy --all-targets` and `cargo test` on macOS CI (even
// though the fuzz crate itself is fine — it disables the `python`
// feature so there's no pyo3 in its link set). With it, every platform
// builds clean and the wheel is unchanged.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
