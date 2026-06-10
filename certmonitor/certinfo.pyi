# type: ignore
"""Stub file for certinfo Rust module to help with type checking."""

from typing import Any, Dict, List

def parse_public_key_info(der_bytes: bytes) -> Dict[str, Any]:
    """Parse public key information from DER bytes."""
    ...

def extract_public_key_der(der_bytes: bytes) -> bytes:
    """Extract public key in DER format."""
    ...

def extract_public_key_pem(der_bytes: bytes) -> str:
    """Extract public key in PEM format."""
    ...

def analyze_chain(chain_ders: List[bytes]) -> Dict[str, Any]:
    """Analyze a certificate chain (list of DER certs)."""
    ...

def pq_algorithms() -> List[Dict[str, Any]]:
    """Return the post-quantum algorithm registry as
    [{"dotted": str, "name": str, "composite": bool}, ...]."""
    ...
