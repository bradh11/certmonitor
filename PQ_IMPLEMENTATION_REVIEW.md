# PQ Implementation Readiness Review

**Scope:** issues #28 (strategy + amendment) and sub-issues #29–#35, verified against the
codebase at `develop` (824243e). Purpose: confirm the plan is implementable as written,
surface the gaps that should be fixed in the issue text *before* the PRs start, and give
each PR concrete, code-grounded implementation guidance.

**Verdict:** the plan is sound and implementable in the proposed order. The two-track
split (cert-side vs. wire-side), the opt-in default, the "hybrid counts as PQ" rule, the
graceful-degradation matrix, and Rust as the single source of truth for IANA tables are
all correct calls and all verified against the real code. There are **two substantive
gaps** that need a decision before the affected PRs land (the `pq_signature` data source,
and the probe's `key_share` strategy), plus a handful of smaller amendments. None of them
invalidate the plan; all of them are cheaper to fix in the issue text now than in PR
review later.

---

## 1. Plan claims verified against the code

Every factual claim the issues make about the codebase checks out:

| Claim (issue) | Verified at |
|---|---|
| SPKI parser only matches RSA/EC OIDs; everything else → `Unknown` | `rust_certinfo/src/x509/spki.rs:74-83` |
| `key_info` returns `is_valid: None` for unrecognized key types | `certmonitor/validators/key_info.py:96-105` |
| `weak_cipher` is suite-allow-list only; TLS 1.3 groups invisible | `certmonitor/validators/weak_cipher.py:52-67` |
| stdlib `ssl` exposes no negotiated TLS 1.3 group; no path in codebase | `protocol_handlers/ssl_handler.py:176-207` (only `cipher()` 3-tuple) |
| Negotiated TLS version is already known Python-side (for the short-circuit) | `ssl_handler.py:57` (`tls_version`), surfaced via `get_cipher_info()["protocol_version"]` (`core.py:537`) |
| Zero-third-party-dependency constraint (Rust: pyo3 only; Python: stdlib only) | `Cargo.toml` `[dependencies]`, `pyproject.toml` `dependencies = []` |
| Chain analysis exists to model `pq_chain` on | `pyobj.rs:148-229` (`analyze_chain_dict`), `validators/chain.py` |
| `cargo test` runs in CI (Rust-heavy PRs 1/4a/4b are actually gated) | `.github/workflows/ci.yml:191` |

Two useful facts the issues *don't* mention but that make the work easier than planned:

- The per-cert dict from `analyze_chain` **already carries** `signature_algorithm_oid`
  and `public_key_info` (`pyobj.rs:68, 104`). `pq_chain` (#35) needs **no new Rust beyond
  PR 1** — it is a pure-Python read over `chain_analysis`, exactly like `chain.py`.
- A fuzz harness already exists (`fuzz/`, `make fuzz`) that links the parser core with
  `--no-default-features` (no PyO3). PR 4a's ServerHello parser should get a second fuzz
  target for free — see §3.4.

---

## 2. Substantive gaps (decide before the affected PR)

### 2.1 `pq_signature` (#31) has no data source for the leaf signature algorithm

The validator spec returns `leaf_sig_alg`, but nothing in `cert_data` reliably contains
it. Validators are pure functions over the dict built by `_fetch_raw_cert()`
(`core.py:174-254`). Today the leaf's signature algorithm OID appears in exactly one
place: `cert_data["chain_analysis"]["certs"][0]["signature_algorithm_oid"]` — and
`chain_analysis` is only populated when the chain could be fetched, which requires
Python ≥ 3.10 (`ssl_handler.py:142-174`). On 3.8/3.9 (`requires-python = ">=3.8,<3.14"`),
`pq_signature` would have **no signature data at all**, and even on modern interpreters
it would silently couple a leaf-only validator to chain retrieval succeeding.

**Recommended fix (zero new Rust):** in `_fetch_raw_cert()`, when `chain_der` is absent
but `self.der` is present, call `certinfo.analyze_chain([self.der])` and store the result
as a leaf-only analysis (either under `chain_analysis` with `chain_length: 1`, or a new
`leaf_analysis` key — the latter is cleaner since it doesn't masquerade as a real chain).
`der` is always available on the SSL path, so this works on every supported interpreter.
Alternative: add a small `parse_cert_summary(der)` `#[pyfunction]`; more surface for the
same data. Either way, **#31's issue text needs a "data source" section** — right now an
implementer can't start it without making this decision implicitly.

### 2.2 Probe `key_share` strategy (#33) can systematically under-report PQ support

#33 says: one `key_share` entry (x25519, garbage bytes) while listing PQ groups in
`supported_groups`. Two problems:

1. **False "classical" results.** Many servers avoid the HelloRetryRequest round-trip and
   accept the offered x25519 share even when they would negotiate `X25519MLKEM768` with a
   client that offered a real hybrid share (this is exactly how browsers behave — they
   send the hybrid share). The probe would then report "classical KEX" for PQ-capable
   servers, which inverts the tool's purpose.
2. **Garbage hybrid shares are not safe.** If the probe ever sends a PQ-group share,
   FIPS 203 requires servers to modulus-check the ML-KEM encapsulation key; invalid bytes
   may draw an alert instead of a ServerHello.

**Recommended fix (stays crypto-free):** embed one precomputed, structurally valid
ML-KEM-768 encapsulation key as a 1,184-byte constant in `probe.rs` and send a real
`X25519MLKEM768` key_share (ML-KEM-768 key ‖ 32-byte x25519 point = 1,216 bytes), with
PQ groups listed first in `supported_groups`. No key generation, no derivation — just a
constant. (An all-zero encapsulation key technically passes the FIPS 203
`ByteDecode₁₂`/re-encode check since 0 < q, but a real precomputed key is
indistinguishable from a normal client and won't trip heuristic filters.) Keep the
x25519 share too so classical-only servers answer without HRR; handle HRR for everything
else, as already planned.

**Related decision to document:** the probe as specified answers *"what is the best this
server will negotiate with a PQ-capable client?"* — not *"what do typical clients get
today?"* (which depends on group order and shares offered). With the hybrid-share fix,
the first question is what `pq_key_exchange` answers. Say so explicitly in #33/#34 and in
the validator docs page, because operators will compare results against browser behavior.

### 2.3 Fixed ClientHello `random` contradicts the WAF-evasion goal

#28/#33 specify a fixed `b"CERTMONITOR-PROBE..."` pattern for `random`/`session_id` while
also requiring "a realistic extension set so WAFs don't drop the probe as a scanner." A
constant random makes every probe byte-identical and trivially fingerprintable/blockable.
A timestamp-derived or `std::collections::hash_map::RandomState`-derived 32-byte fill
costs nothing, needs no CSPRNG and no new dependency, and removes the static signature.
(Keeping a recognizable `session_id` for politeness/debuggability is fine — that field is
legacy-only in TLS 1.3.)

---

## 3. Per-PR implementation guidance

### PR 1 — #29: PQ OIDs in the SPKI parser (Track A root)

- **OIDs (NIST CSOR arc `2.16.840.1.101.3.4.3`, DER prefix
  `60 86 48 01 65 03 04 03` + final arc):**
  - ML-DSA-44 / 65 / 87 → `.17` / `.18` / `.19`
  - SLH-DSA (12 parameter sets) → `.20`–`.31` (sha2-128s/f, sha2-192s/f, sha2-256s/f,
    shake-128s/f, shake-192s/f, shake-256s/f)
  - Falcon: no stable codepoints — stub with TODO per the issue; don't guess.
  - Composite signatures: the draft-ietf-lamps-pq-composite-sigs OIDs (Entrust arc
    `2.16.840.1.114027.80.8.1.*`) **have changed between draft revisions**. Pin the
    draft revision in a comment next to the table, and isolate composites in their own
    clearly-marked block so a registry shift is a table edit, not a code change.
- **Dict shape decision needed:** `key_info_dict` (`pyobj.rs:24-50`) returns
  `{algorithm, size, curve}`. For ML-DSA/SLH-DSA there is no modulus and no curve.
  Recommendation: `algorithm` = lowercase name (`"ml-dsa-65"`, `"slh-dsa-sha2-128s"`),
  `size` = `subject_public_key.len() * 8` (consistent "bits of key material"; ML-DSA-65 →
  15,616), `curve` = `None` — and document that PQ strength is judged by *algorithm
  identity*, never by `size`. This honors #29's "no shape change" rule (only new
  `algorithm` string values), but the semantics of `size` for PQ must be written down or
  the #30 tests will encode an accident.
- For ML-DSA/SLH-DSA the SPKI algorithm OID and the certificate `signatureAlgorithm` OID
  are the same values with absent parameters — one OID table serves both #29 and #31.
  `AlgorithmIdentifier::parse_inner` (`algorithm.rs:32-55`) already treats absent
  parameters correctly; no changes needed there.
- Extend `PublicKeyAlgorithm` (`spki.rs:32-37`) with variants like
  `MlDsa { variant: MlDsaVariant }` / `SlhDsa { variant: ... }` rather than one
  stringly-typed variant — `match` exhaustiveness then enforces `pyobj.rs` coverage.
- Regression guard: `chain.py` and `root_certificate_validator.py` consume
  `public_key_info` transparently; the corpus test (`tests/test_certinfo_corpus.py`)
  should pass untouched. Run it before and after.

### PR 2 — #30: `key_info` recognizes PQ

- Touch point is exactly `_is_key_strong_enough` (`key_info.py:82-105`). Note the
  existing style is substring matching (`"rsaEncryption" in key_type`); for PQ use exact
  set membership against a module-level `frozenset` of PQ algorithm names (mirroring
  `_DEFAULT_WEAK_SIG_OIDS` in `chain.py:10-18`). Substring matching is how
  `"slh-dsa-sha2-128s"` ends up matching a future unrelated name.
- The issue's edge case "unknown PQ algorithm still returns `is_valid: None`" is right —
  keep `None` as "we don't know", reserve `False` for "we know it's weak".

### PR 3 — #31: `pq_signature`

- Blocked on the §2.1 data-source decision; otherwise straightforward.
- **Semantics alignment with #35 (do it now, in the issue text):** #31 requires *both*
  leaf key alg AND sig alg PQ for `is_valid: True`; #35 defaults to "leaf PQ is enough"
  where leaf means key alg. During migration, a PQ-keyed leaf signed by a classical CA
  (the realistic 2026 case — the sig alg is the *CA's* choice, not the operator's) would
  **fail `pq_signature` and pass `pq_chain`**. Recommendation: make `pq_signature`'s
  default judge what the operator controls (leaf key alg), report `leaf_sig_alg` +
  `is_pq_signed` as data, and offer `require_pq_signature: bool = False` as a
  keyword-only user arg (the `base.py` `__init_subclass__` machinery gives arg validation
  and `describe_validators()` output for free).

### PR 4a — #32: `tls/` parsers (no networking)

- Seed `groups.rs` with at least: `0x0017` secp256r1, `0x0018` secp384r1, `0x0019`
  secp521r1, `0x001D` x25519, `0x001E` x448, `0x0100`–`0x0104` ffdhe2048–8192
  (ClassicalFfdh), `0x11EB` SecP256r1MLKEM768, `0x11EC` X25519MLKEM768, `0x11ED`
  SecP384r1MLKEM1024 (HybridPq), `0x0200`–`0x0202` ML-KEM-512/768/1024 (PurePq), and
  `0x6399` X25519Kyber768Draft00 (HybridPq, legacy draft — still seen on long-tail
  servers in 2026; classify it hybrid, name it distinctly).
- HRR detection: RFC 8446 §4.1.4 — HelloRetryRequest *is* a ServerHello whose `random`
  equals the fixed §4.1.3 magic value. The parser must distinguish "server selected a
  group" (ServerHello `key_share` extension) from "server requests a different group"
  (HRR `key_share` carries the requested NamedGroup). Both carry the answer the probe
  wants; an HRR requesting a PQ group is itself a positive capability signal.
- **Add a fuzz target.** `fuzz/` already builds the crate with `default-features =
  false`; a `fuzz_targets/parse_server_hello.rs` is ~10 lines and directly serves #33's
  "never panics on adversarial input" DoD. Add the make plumbing (or run it under the
  existing target) in this PR while the parser is fresh.
- Reuse `DerReader`'s bounded-read discipline (`der/reader.rs`) as the model for
  `TlsHandshakeReader`, but don't force-fit: TLS uses 2/3-byte big-endian lengths, not
  DER TLV. A small dedicated reader is correct, as the issue anticipates.

### PR 4b — #33: `probe.rs` + PyO3 export

- Apply §2.2 (real hybrid key_share) and §2.3 (non-constant random).
- **Release the GIL.** The probe blocks on connect/read for up to `timeout_ms`. Wrap the
  socket work in `py.allow_threads(...)` or concurrent scans (the README's headline use
  case) will serialize on the probe.
- **Error convention tension to resolve:** existing `#[pyfunction]`s raise `PyValueError`
  (`pyobj.rs:16-18`); #33 specifies returning `{error, message}` dicts. Pick one: the
  cleanest is for the Rust function to return a dict in *all* terminal states (success,
  n/a, error) and never raise except on internal bugs — that matches the validator-facing
  contract in #34 and avoids try/except at every call site. Document the choice in
  `probe.rs`.
- `TcpStream::connect_timeout` takes a single `SocketAddr` — resolve via
  `to_socket_addrs()` and iterate (try each address, first success wins), and state
  whether `timeout_ms` bounds the whole probe or each phase (recommend: whole probe;
  enforce with a deadline check between connect/write/read).
- SNI: skip the `server_name` extension when `sni` parses as an IP literal — RFC 6066
  forbids IP literals in SNI, and `CertMonitor` already knows (`core.py:33`,
  `_is_ip_address`). Make `sni: Option<&str>` and let the Python caller decide.
- Default timeout: issue says 5000 ms; everything else in the codebase uses 10 s
  (`core.py:105`, `ssl_handler.py:52`). Minor, but align (recommend 10 000 ms) or note
  why the probe is tighter.
- **Update `certmonitor/certinfo.pyi`** with `probe_tls_handshake` — note the stub is
  *already stale* (missing `analyze_chain`); fix that here too since mypy runs in CI.
- Operational note for the docs page: this is a **second TCP connection per scan**, which
  IDS/rate-limiters will see. Opt-in default already mitigates; say it out loud.

### PR 5 — #34: `pq_key_exchange`

- **Dispatcher reality check:** `validate()` (`core.py:552-639`) has exactly two
  branches — cert validators get `cert_data`, cipher validators get `cipher_info`.
  A cipher-type `pq_key_exchange` receives `(cipher_info, host, port)`, so the *minimal*
  implementation works without touching the dispatcher: read `protocol_version` from
  `cipher_info` for the short-circuit, then call `certinfo.probe_tls_handshake(host,
  port, ...)` itself. That is what the issue implies, and it's acceptable for one
  validator — but it makes this the only validator that does network I/O inside
  `validate()`, which breaks the pure-function-over-fetched-data property that makes
  every existing validator trivially testable, and the probe result can't be shared with
  the future `tls_kex_curve` (#28 amendment item 7) without a second connection.
- **Recommended (small, optional, before or with this PR):** generalize the dispatch to
  declared data requirements — validators declare e.g. `requires =
  frozenset({"cipher_info", "tls_probe"})`; the dispatcher keeps a registry of source
  fetchers, lazily fetches + memoizes each source once per `validate()` call, and
  injects. `BaseCertValidator`/`BaseCipherValidator` become one-line shims
  (`requires = {"cert_info"}`), so existing custom validators don't break. This also
  fixes a real existing inconsistency: cert-source failure writes a structured error
  result per validator (`core.py:608-619`) while cipher-source failure **silently omits**
  those validators from the results dict (`core.py:629-632`) — a monitoring pipeline
  doing `results["weak_cipher"]` gets a `KeyError` instead of a failure record. Under the
  data-source model the rule is uniform: source fails → every dependent validator gets
  the structured error. If the refactor is deferred, fix the silent-omission bug anyway;
  it bites `pq_key_exchange` on every TLS-1.2 short-circuit test otherwise written
  against `get_cipher_info()` errors.
- Free API win while here: `get_cipher_info()` currently returns
  `key_exchange_algorithm: "Not applicable (TLS 1.3 uses ephemeral key exchange by
  default)"` (`core.py:541-544`). Once the probe exists, that placeholder is exactly
  where the negotiated group name belongs.
- Behavior matrix in #34 is complete and the strict-`bool` `is_valid` decision from the
  amendment is right. One addition: an **HRR response that requests a PQ group** should
  count as PQ-capable (see PR 4a note) — add a matrix row.

### PR 6 — #35: `pq_chain`

- Model on `chain.py` as planned; the data is already in `chain_analysis` per cert
  (`signature_algorithm_oid`, `public_key_info`) once PR 1 lands. No new Rust.
- Add the interpreter-version row explicitly: on 3.8/3.9 `chain_analysis` is `None`
  (`ssl_handler.py:171-174`) and the validator must return the structured error — the
  `chain.py:115-130` pattern handles this; copy the test too.
- Resolve the open `is_valid` question consistently with §3 PR 3: default (1) "leaf PQ
  (key alg) is enough", plus a keyword-only threshold arg if wanted later. Keep the
  trust-anchor caveat ("root will be classical for years — expected, not a bug") in both
  docstring and docs page, as the issue already requires.

---

## 4. Cross-cutting items

- **Result envelope drift.** Existing validators return ad-hoc shapes (`{is_valid,
  reason}`, `{error, message}`, bespoke keys). Four new PQ validators are about to add
  four more. A one-page documented contract (`is_valid: bool` always present; `reason`
  on failure; everything else namespaced data) adopted by the *new* validators costs
  nothing now and gives a migration target for the old ones. A `TypedDict` lets mypy
  (already in CI, `python_version = 3.8` — mind the typing syntax) enforce it.
- **Docs/nav:** each validator PR adds a page under `docs/validators/` + `mkdocs.yml`
  nav entry (already in each DoD — pattern confirmed at `mkdocs.yml:26-36`).
- **Coverage gate is real:** `pytest --cov-fail-under=95` (Makefile `test`). The probe
  PR's Python-visible surface is one function; its coverage lives in #34's mocked tests —
  fine, but don't let `certinfo.pyi` typos hide behind `# type: ignore`.
- **`make ci` doesn't run `cargo test`** (GitHub CI does, at `ci.yml:191`). For
  Rust-heavy PRs 1/4a/4b, either add `cargo test` to the Makefile `test` target or note
  in the PR template that local `make ci` under-checks Rust.

## 5. Recommended sequence (updated)

Unchanged spine, three insertions:

1. **#29** Rust SPKI OIDs — *amend first: dict-shape semantics for `size` (§3 PR 1)*
2. **#30** `key_info` PQ recognition
3. **#31** `pq_signature` — *amend first: data source (§2.1) + semantics alignment (§3 PR 3)*
4. **#32** `tls/` parsers — *add fuzz target while in there*
5. **(new, small)** dispatcher data-source refactor **or** at minimum the
   cipher-failure silent-omission fix (`core.py:629-632`)
6. **#33** `probe.rs` — *amend first: hybrid key_share (§2.2), random (§2.3), GIL,
   error convention, `.pyi`*
7. **#34** `pq_key_exchange` — *add HRR-positive matrix row*
8. **#35** `pq_chain` — *resolve `is_valid` consistently with #31*

Parallelism as planned: (1–3) and (4–7) are independent tracks; day-1 start on #29 + #32
holds.
