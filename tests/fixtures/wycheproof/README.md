# Wycheproof vectors

Signature test vectors from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1/`), reduced to the fields `tests/test_wycheproof.py` reads.
Licensed under Apache 2.0 by the Wycheproof authors.

Every test keeps `tcId`, `msg`, `sig`, `result`, `flags`, and `comment`. Test
groups come in three shapes, and a group keeps whichever fields its own file
carries:

- ECDSA and RSASSA-PKCS1-v1_5: `publicKeyDer` and `sha`.
- RSASSA-PSS: those two plus `mgf`, `mgfSha`, and `sLen`, which
  `tests.support.pss_params` encodes into `RSASSA-PSS-params` (RFC 4055
  section 3.1) since the vectors carry no parameters of their own.
- EdDSA: `publicKeyDer` alone. RFC 8032 fixes the hash, so there is no `sha`,
  and both files carry the algorithm name `EDDSA`, so the curve comes from
  the key.

Regenerate by downloading an original and running `slim.py`, which writes the
reduced file next to itself:

```sh
gh api repos/C2SP/wycheproof/contents/testvectors_v1/<name> --jq .content \
    | base64 -d > /tmp/<name>
python tests/fixtures/wycheproof/slim.py /tmp/<name>
```

Then add the file name to `test_vector_files_are_complete` in
`tests/test_wycheproof.py`, which asserts the directory listing exactly.
