# SSH scanner review: mechanics, cleanup, and how it could fold into CertMonitor

Reviewed: `~/Documents/code/ssh-scanner` at commit 9745bb4 ("Enhance SSHScanner with improved key exchange algorithms and error handling"). This is a research note; nothing from that repo has been folded into CertMonitor.

## What it does

`SSHScanner(hostname, port=22, timeout=5)` speaks enough of SSH-2 to learn what a server offers and to fetch its host key:

1. `connect()` resolves the host (IPv4 and IPv6), opens a socket, exchanges identification strings (`SSH-2.0-PythonSSHScanner_1.0`).
2. Sends `SSH_MSG_KEXINIT` offering every algorithm in `algorithms.py` (ordered strongest to weakest, deliberately including deprecated ones so weak servers can be observed), reads the server's KEXINIT, and negotiates each algorithm class the way RFC 4253 section 7.1 prescribes (first client preference the server also lists).
3. Runs the key exchange for the negotiated method so the server sends its host key:
   - `diffie-hellman-group1/14/16/18-*`: classic DH with the RFC 2409/3526 primes inlined as hex constants; modular exponentiation in pure Python.
   - `diffie-hellman-group-exchange-*`: requests a group, then DH.
   - `curve25519-sha256*` and `ecdh-sha2-nistp256/384/521`: ephemeral keys and shared secrets computed by the Rust extension (`ssh_rust_lib`).
4. Computes the exchange hash and parses the server host key blob (`_parse_server_host_key`): RSA (e, n, bit length), Ed25519, ECDSA (curve, point), DSA; records algorithm, key type, key length, components, and a SHA-256 fingerprint of the raw blob.
5. `get_server_info()` returns the offered algorithm lists, the negotiated choices, the host key details, and any warnings. Two validators exist (`key_info`, `dh_compliance`) with a tiny registry mirroring CertMonitor's early validator design.

Tests (18) run against Docker containers (`docker-compose.yml`, eleven `sshd_config_*` variants: default, strong, weak, dsa, rsa, ecdsa, ed25519, chacha20, hmac-sha2-512, mismatch) and are skipped or fail loudly without Docker.

## What is sound and reusable

- The wire-level parts are correct and compact: identification exchange, binary packet framing (`_send_packet`, `_read_packet`, `_recv_all`), name-list encoding, KEXINIT construction and parsing, and the RFC 4253 negotiation rule. About 300 lines that could move almost verbatim.
- The host key blob parser is complete for the key types that matter and already produces a SHA-256 fingerprint, which lines up with `fingerprint_sha256` in CertMonitor.
- The algorithm catalog in `algorithms.py` is a good seed for "weak KEX", "weak host key", "weak cipher", and "weak MAC" validators, the SSH analogue of `tls_version` and `weak_cipher`.
- The container matrix is a good model for the opt-in integration suite CertMonitor is about to gain for STARTTLS.

## What needs cleanup before any of it ships

- **Third-party Rust crates.** `rust_lib` depends on `rand`, `x25519-dalek`, `ed25519-dalek`, `p256`, `p384`, `p521`, and `elliptic-curve`. CertMonitor's Rust tree is pyo3-only by policy, so the ECDH parts cannot come across as they are.
- **Error handling.** Bare `Exception` everywhere, a `print("DEBUG: ...")` on the host key path, and failures folded into `server_host_key = {"error": ...}` without a status. CertMonitor's structured error dicts and `status` envelope should replace all of it.
- **Blocking I/O.** `_receive_version` reads one byte at a time with no bound; `_recv_all` can hang if a server stalls mid-packet; there is one timeout for the whole session rather than per operation.
- **Stubbed behavior.** `diffie-hellman-group1-sha1` skips key exchange entirely and returns an empty host key "for legacy tests".
- **Size.** `ssh_scanner.py` is 1,165 lines; roughly 600 are the DH and ECDH exchange plus the exchange-hash code, much of it repeated per group with the primes inlined.
- **Packaging.** Poetry-based, pyo3 0.18 with `abi3-py38`, a checked-in `.so`, and `.DS_Store` files in the tree.

## The key insight for CertMonitor: the host key does not require a shared secret

To obtain and fingerprint an SSH host key, a client only needs to send a syntactically valid ephemeral public value in `SSH_MSG_KEX_ECDH_INIT`; the server replies with its host key blob, its own ephemeral value, and a signature. Parsing the host key and computing its fingerprint needs no cryptography at all. The shared secret is only required to verify the server's signature over the exchange hash.

That means CertMonitor can offer SSH host-key collection, fingerprinting, algorithm inventory, and weak-algorithm validators with the standard library alone. Signature verification (proving the server holds the private key) would need X25519 plus Ed25519/ECDSA/RSA verification, which is the one place an in-tree Rust implementation would be warranted later, exactly as the in-house DER parser replaced third-party parsing crates.

## Suggested shape inside CertMonitor (for later)

- `SSHHandler.connect()` already reads the banner. Extend it to run the KEXINIT exchange and a "collect-only" ECDH init, returning `{"protocol": "ssh", "server_version", "algorithms": {...}, "negotiated": {...}, "host_key": {"algorithm", "key_type", "key_length", "fingerprint_sha256"}}` as the raw collection, structured the way `fetch_raw_cert()` returns TLS data.
- New `requires = ("ssh_info",)` validators: `ssh_host_key` (type and size policy), `ssh_kex`, `ssh_cipher`, `ssh_mac` (allow-lists like `weak_cipher`), reusing the envelope and `status` codes. The existing TLS validators would report `unsupported` for SSH targets, as they do today.
- `certmonitor check host:22` would work unchanged; protocol detection already recognizes the `SSH-` banner.
- Keep the door open by not overloading `starttls` for SSH: SSH is its own protocol handler, not a TLS preamble. The connection options that make sense for both (`connection_host`, `timeout`) already live on the monitor.

## Effort estimate

Collection and fingerprinting with validators and docs: about two days, standard library only. Signature verification via in-tree Rust: another two to three days, and it should be justified by a concrete need (detecting a man-in-the-middle presenting a copied host key) before it is built.
