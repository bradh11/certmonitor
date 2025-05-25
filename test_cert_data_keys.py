#!/usr/bin/env python3
"""Test script to verify that public keys are included in cert_data."""

import json
from certmonitor import CertMonitor


def test_cert_data_includes_public_keys():
    """Test that cert_data includes public_key_der and public_key_pem."""

    with CertMonitor("example.com") as monitor:
        # Get certificate info
        cert_info = monitor.get_cert_info()
        cert_data = monitor.cert_data

        print("=== Testing cert_data includes public keys ===")
        print(f"cert_info is not None: {cert_info is not None}")
        print(f"cert_data is not None: {cert_data is not None}")

        # Check if public keys are in cert_data
        has_der_in_data = "public_key_der" in cert_data
        has_pem_in_data = "public_key_pem" in cert_data

        print(f"'public_key_der' in cert_data: {has_der_in_data}")
        print(f"'public_key_pem' in cert_data: {has_pem_in_data}")

        if has_der_in_data:
            der_key = cert_data["public_key_der"]
            print(f"cert_data['public_key_der'] type: {type(der_key)}")
            print(
                f"cert_data['public_key_der'] length: {len(der_key) if der_key else 'None'} bytes"
            )

        if has_pem_in_data:
            pem_key = cert_data["public_key_pem"]
            print(f"cert_data['public_key_pem'] type: {type(pem_key)}")
            print(
                f"cert_data['public_key_pem'] length: {len(pem_key) if pem_key else 'None'} characters"
            )

        # Verify they match the instance attributes
        der_match = cert_data.get("public_key_der") == monitor.public_key_der
        pem_match = cert_data.get("public_key_pem") == monitor.public_key_pem

        print(
            f"cert_data['public_key_der'] matches monitor.public_key_der: {der_match}"
        )
        print(
            f"cert_data['public_key_pem'] matches monitor.public_key_pem: {pem_match}"
        )

        # Show the keys
        if has_pem_in_data and cert_data["public_key_pem"]:
            print("\nPEM Key from cert_data:")
            print(cert_data["public_key_pem"])

        return has_der_in_data and has_pem_in_data and der_match and pem_match


if __name__ == "__main__":
    success = test_cert_data_includes_public_keys()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")
