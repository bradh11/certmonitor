# Wycheproof vectors

Signature test vectors from [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(`testvectors_v1/`), reduced to the fields `tests/test_wycheproof.py` reads:
the DER public key, the hash, and each test's message, signature, expected result,
flags, and comment. Licensed under Apache 2.0 by the Wycheproof authors.

Regenerate by downloading the originals and running the slimming step in the
commit that added this directory.
