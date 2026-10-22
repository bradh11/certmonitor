# eMudhra intermediates (October 2026)

The eight eMudhra intermediate CA certificates whose P-384 private keys were
generated as integers below 256 and revoked in October 2026
([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)).
They come from `proof.zip` at <https://emudhra.we-have-a-problem.com/>,
captured on 2026-10-21. Public certificates only; no private keys are stored
here.

The private scalars were found without CertMonitor, by building a SEC 1
private key for each of 1 to 1024 and comparing `openssl ec -pubout` with each
certificate's public key:

| Certificate | Scalar |
|---|---|
| EM DV TLS CA - G3B | 156 |
| EM DV TLS CA - G3C | 230 |
| EM EV TLS CA - G3B | 115 |
| EM EV TLS CA - G3C | 56 |
| EM OV CS CA - G3B | 66 |
| EM OV CS CA - G3C | 237 |
| EM OV TLS CA - G3B | 155 |
| EM OV TLS CA - G3C | 4 |

## Served chains

`chains/` holds two of the chains the incident's test hosts served, from
`chains.zip` at the same site, leaf first:

- `dv-g3b-emudhra.we-have-a-problem.com.pem`: leaf, EM DV TLS CA - G3B
  (scalar 156), and emSign Root TLS CA - G3 cross-signed by emSign ECC Root
  CA - G3.
- `ov-g3c-aaa-emudhra.we-have-a-problem.com.pem`: leaf and EM OV TLS CA - G3C
  cross-signed by AAA Certificate Services (the same key, scalar 4).
