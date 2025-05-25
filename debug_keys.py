#!/usr/bin/env python3
"""Debug script to check public key extraction step by step."""

from certmonitor import CertMonitor


def debug_public_key_extraction():
    """Debug the public key extraction process."""
    print("=== Debug Public Key Extraction ===")

    with CertMonitor("example.com") as monitor:
        print(f"1. After connection:")
        print(f"   public_key_der: {monitor.public_key_der}")
        print(f"   public_key_pem: {monitor.public_key_pem}")
        print(
            f"   cert_data: {hasattr(monitor, 'cert_data')} -> {getattr(monitor, 'cert_data', 'NOT_SET')}"
        )

        print(f"\n2. Calling _fetch_raw_cert directly:")
        try:
            raw_cert_data = monitor._fetch_raw_cert()
            print(
                f"   raw_cert_data keys: {raw_cert_data.keys() if isinstance(raw_cert_data, dict) else 'NOT_DICT'}"
            )
            print(
                f"   public_key_der after _fetch_raw_cert: {monitor.public_key_der is not None}"
            )
            print(
                f"   public_key_pem after _fetch_raw_cert: {monitor.public_key_pem is not None}"
            )
        except Exception as e:
            print(f"   Error in _fetch_raw_cert: {e}")

        print(f"\n3. Calling get_cert_info:")
        try:
            cert_info = monitor.get_cert_info()
            print(f"   cert_info retrieved: {cert_info is not None}")
            print(
                f"   public_key_der after get_cert_info: {monitor.public_key_der is not None}"
            )
            print(
                f"   public_key_pem after get_cert_info: {monitor.public_key_pem is not None}"
            )

            if monitor.public_key_der:
                print(f"   DER length: {len(monitor.public_key_der)}")
            if monitor.public_key_pem:
                print(f"   PEM length: {len(monitor.public_key_pem)}")

        except Exception as e:
            print(f"   Error in get_cert_info: {e}")
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    debug_public_key_extraction()
