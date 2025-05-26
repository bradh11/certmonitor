# cipher_algorithms.py

import re
from functools import lru_cache
from typing import Any, Dict, Optional, Pattern, Set, Union, cast

"""
This module defines:
- Patterns for parsing cipher suites into their components.
- Centrally managed allowed TLS versions and cipher suites.
- Functions to update these allowed lists at runtime.

By using allowed lists, the validator fails if the target negotiates
a version or cipher suite not present in these lists.

Users and maintainers can:
1. View current algorithms using `list_algorithms()`.
2. Update cipher parsing patterns using `update_algorithms()`.
3. Update allowed TLS versions and cipher suites using `update_allowed_lists()`.

Default values are based on commonly accepted industry standards.
"""

# Type alias for the algorithms dictionary (can contain either strings or compiled patterns)
AlgorithmDict = Dict[str, Union[str, Pattern[str]]]

ALL_ALGORITHMS: Dict[str, AlgorithmDict] = {
    "encryption": {
        "AES": r"AES",
        "CHACHA20": r"CHACHA20",
        "3DES": r"3DES|DES-EDE3",
        "CAMELLIA": r"CAMELLIA",
        "ARIA": r"ARIA",
        "SEED": r"SEED",
        "SM4": r"SM4",
        "IDEA": r"IDEA",
        "RC4": r"RC4",
    },
    "key_exchange": {
        "ECDHE": r"ECDHE|EECDH",
        "DHE": r"DHE|EDH",
        "ECDH": r"ECDH",
        "DH": r"DH",
        "RSA": r"RSA",
        "PSK": r"PSK",
        "SRP": r"SRP",
        "GOST": r"GOST",
        "ECCPWD": r"ECCPWD",
        "SM2": r"SM2",
    },
    "mac": {
        "SHA384": r"SHA384",
        "SHA256": r"SHA256",
        "SHA224": r"SHA224",
        "SHA": r"SHA1?",  # Matches 'SHA' or 'SHA1'
        "MD5": r"MD5",
        "POLY1305": r"POLY1305",
        "AEAD": r"GCM|CCM|OCB",
        "GOST": r"GOST28147|GOST34\.11",
        "SM3": r"SM3",
    },
}

# Compile all regex patterns
for category in ALL_ALGORITHMS.values():
    for alg, pattern in category.items():
        category[alg] = re.compile(pattern)


@lru_cache(maxsize=128)
def parse_cipher_suite(cipher_suite: str) -> Dict[str, str]:
    """
    Parse a cipher suite string to identify encryption, key exchange, and MAC algorithms.
    """
    result = {"encryption": "Unknown", "key_exchange": "Unknown", "mac": "Unknown"}

    for category, algorithms in ALL_ALGORITHMS.items():
        for alg, pattern in algorithms.items():
            # At runtime, patterns are compiled regex objects after initialization
            compiled_pattern = cast(Pattern[str], pattern)
            if compiled_pattern.search(cipher_suite):
                result[category] = alg
                break

    return result


def list_algorithms() -> Dict[str, Any]:
    """
    List all known algorithms by category.
    """
    alg_list = {}
    for category, alg_dict in ALL_ALGORITHMS.items():
        alg_list[category] = list(alg_dict.keys())
    return alg_list


def update_algorithms(custom_algorithms: Dict[str, Dict[str, str]]) -> None:
    """
    Update the ALL_ALGORITHMS dictionary with user-provided custom algorithms.
    """
    global ALL_ALGORITHMS

    for category, algs in custom_algorithms.items():
        if category not in ALL_ALGORITHMS:
            ALL_ALGORITHMS[category] = {}
        for alg_name, pattern in algs.items():
            ALL_ALGORITHMS[category][alg_name] = re.compile(pattern)

    parse_cipher_suite.cache_clear()


# Default allowed lists for TLS versions and cipher suites.
# If a negotiated version or cipher is not in these sets, validation fails.
ALLOWED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

ALLOWED_CIPHER_SUITES = {
    # Following industry guidelines (e.g., Mozilla's "Intermediate" TLS configuration)
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
}


def update_allowed_lists(
    custom_tls_versions: Optional[Set[str]] = None,
    custom_ciphers: Optional[Set[str]] = None,
) -> None:
    """
    Update the sets of allowed TLS versions and cipher suites.

    Args:
        custom_tls_versions (set): A set of allowed TLS versions. E.g., {"TLSv1.2", "TLSv1.3"}
        custom_ciphers (set): A set of allowed cipher suites. E.g., {"ECDHE-RSA-AES128-GCM-SHA256"}
    """
    global ALLOWED_TLS_VERSIONS, ALLOWED_CIPHER_SUITES
    if custom_tls_versions is not None:
        ALLOWED_TLS_VERSIONS = custom_tls_versions

    if custom_ciphers is not None:
        ALLOWED_CIPHER_SUITES = custom_ciphers
