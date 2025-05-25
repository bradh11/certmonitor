#!/usr/bin/env python3
"""Test script to verify public key extraction functionality."""

import json
from certmonitor import CertMonitor


def test_public_key_extraction():
    """Test public key extraction in DER and PEM formats."""
    validators = [
        "subject_alt_names",
        "expiration",
        "hostname",
        "root_certificate",
        "key_info",
    ]

    with CertMonitor(
        "onug2025.ntc-workshops.com", enabled_validators=validators
    ) as monitor:
        # Get certificate info to trigger key extraction
        cert_info = monitor.get_cert_info()

        # Test the new methods
        public_key_der = monitor.get_public_key_der()
        public_key_pem = monitor.get_public_key_pem()

        print("=== Public Key Information ===")
        print(f"Certificate loaded: {cert_info is not None}")
        print(f"Public Key DER extracted: {public_key_der is not None}")
        print(f"Public Key PEM extracted: {public_key_pem is not None}")

        if public_key_der:
            print(f"DER length: {len(public_key_der)} bytes")
            print(f"DER first 20 bytes (hex): {public_key_der[:20].hex()}")
            print(f"DER type: {type(public_key_der)}")

        if public_key_pem:
            print(f"PEM length: {len(public_key_pem)} characters")
            print("PEM format:")
            print(public_key_pem)

        # Check if they're stored in the instance
        print("\n=== Instance Attributes ===")
        print(f"self.public_key_der is not None: {monitor.public_key_der is not None}")
        print(f"self.public_key_pem is not None: {monitor.public_key_pem is not None}")

        if monitor.public_key_der:
            print(f"Instance DER length: {len(monitor.public_key_der)} bytes")
        if monitor.public_key_pem:
            print(f"Instance PEM length: {len(monitor.public_key_pem)} characters")


if __name__ == "__main__":
    test_public_key_extraction()
