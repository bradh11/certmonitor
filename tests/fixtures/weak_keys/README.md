# RSA keys with recognizable weaknesses

Self-signed test certificates for the `weak_keys` validator. Each key was
built offline from known primes, checked with `openssl rsa -check`, and used
once to sign its certificate; the private keys were not kept.

- `close-primes.crt.pem`: a 2047-bit modulus whose primes differ by less than
  2000, so Fermat's method factors it at once (the CVE-2022-26320 pattern).
- `roca.crt.pem`: a 2048-bit modulus whose primes have the Infineon RSALib
  structure `k * M + (65537^a mod M)` (CVE-2017-15361). The reference
  detector, `roca-detect`, flags it, and flags neither the close-primes key
  nor the RSA keys in `tests/fixtures/chain_1.der` and `chain_2.der`.
