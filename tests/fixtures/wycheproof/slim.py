"""Reduce a downloaded Wycheproof signature file to the fields the tests read.

The originals in `C2SP/wycheproof/testvectors_v1/` carry the public key in
four encodings, a prose header, and per-group notes. `tests/test_wycheproof.py`
reads only the DER key, the hash and PSS parameters, and each test's message,
signature, expected result, flags, and comment, so everything else is dropped
before the file is checked in.

Fetch an original and slim it next to this script with:

    gh api repos/C2SP/wycheproof/contents/testvectors_v1/<name> --jq .content \\
        | base64 -d > /tmp/<name>
    python tests/fixtures/wycheproof/slim.py /tmp/<name>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Group fields, in the order they are written out. `sha` is absent from EdDSA
# files (RFC 8032 fixes the hash), and `mgf`, `mgfSha`, and `sLen` appear only
# in RSASSA-PSS files, so a group keeps whichever of these it has.
GROUP_FIELDS = ("publicKeyDer", "sha", "mgf", "mgfSha", "sLen")
TEST_FIELDS = ("tcId", "msg", "sig", "result", "flags", "comment")


def slim(raw: dict) -> dict:
    """The slimmed file: the algorithm, the groups, and a test count."""
    groups = []
    for group in raw["testGroups"]:
        kept = {name: group[name] for name in GROUP_FIELDS if name in group}
        kept["tests"] = [
            {name: test[name] for name in TEST_FIELDS if name in test}
            for test in group["tests"]
        ]
        groups.append(kept)
    return {
        "algorithm": raw["algorithm"],
        # The v1 originals carry no top-level `source`, and
        # `test_vector_files_are_complete` reads `numberOfTests`, so both are
        # written out to match the shape every fixture in this directory has.
        "source": raw.get("source", {}),
        "testGroups": groups,
        "numberOfTests": sum(len(group["tests"]) for group in groups),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <downloaded wycheproof json>")
        return 2
    source = Path(argv[1])
    slimmed = slim(json.loads(source.read_text()))
    destination = Path(__file__).resolve().parent / source.name
    destination.write_text(json.dumps(slimmed, indent=1) + "\n")
    print(f"wrote {destination} with {slimmed['numberOfTests']} tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
