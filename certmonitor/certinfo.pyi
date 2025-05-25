# type: ignore
"""Stub file for certinfo Rust module to help with type checking."""

from typing import Any, Dict

def parse_public_key_info(der_bytes: bytes) -> Dict[str, Any]:
    """Parse public key information from DER bytes."""
    ...

def extract_public_key_der(der_bytes: bytes) -> bytes:
    """Extract public key in DER format."""
    ...

def extract_public_key_pem(der_bytes: bytes) -> str:
    """Extract public key in PEM format."""
    ...
