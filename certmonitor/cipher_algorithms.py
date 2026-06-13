# cipher_algorithms.py

import re
from functools import lru_cache
from typing import Any, Dict, Pattern, Union, cast

"""
This module defines the patterns for parsing a negotiated cipher suite
name into its components (encryption, key exchange, MAC), used by
``CertMonitor.get_cipher_info`` for the structured cipher breakdown.

Users and maintainers can:
1. View current algorithms using `list_algorithms()`.
2. Update cipher parsing patterns using `update_algorithms()`.

The acceptable TLS versions and cipher suites are policy owned by their
validators (`tls_version` and `weak_cipher`), each configurable per call
via validator arguments, rather than global state here.
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
