import json

from certmonitor import CertMonitor

# Example usage
if __name__ == "__main__":
    # Test with a hostname
    with CertMonitor("example.com") as monitor:
        cert_data = monitor.get_cert_info()
        validation_results = monitor.validate(
            validator_args={"subject_alt_names": ["www.example.com"]}
        )
        # public_key_info = monitor._extract_public_key_info()
        print("Hostname test:")
        print(monitor.cert_data)

        # Test public key extraction
        print("\nPublic Key Extraction Test:")
        print(f"  public_key_der available: {monitor.public_key_der is not None}")
        print(f"  public_key_pem available: {monitor.public_key_pem is not None}")
        if monitor.public_key_der:
            print(f"  DER length: {len(monitor.public_key_der)} bytes")
        if monitor.public_key_pem:
            print(f"  PEM length: {len(monitor.public_key_pem)} characters")
            print(f"  PEM format:\n{monitor.public_key_pem}")

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv4 address
    with CertMonitor("20.76.201.171") as monitor:  # IPv4 for example.com
        cert = monitor.get_cert_info()
        validation_results = monitor.validate()
        print("IPv4 test:")
        print(json.dumps(cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an IPv6 address
    with CertMonitor(
        "2606:2800:220:1:248:1893:25c8:1946"
    ) as monitor:  # IPv6 for example.com
        cert = monitor.get_cert_info()
        validation_results = monitor.validate()
        print("IPv6 test:")
        print(json.dumps(cert, indent=2))

    print("\n" + "=" * 50 + "\n")

    # Test with an hostname with very few SANS
    with CertMonitor(
        "www.networktocode.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    ) as monitor:
        cert = monitor.get_cert_info()
        validation_results = monitor.validate(
            validator_args={"subject_alt_names": ["networktocode.com"]}
        )
        print("Hostname with few SANS:")
        print(json.dumps(cert, indent=2))

    # Test with an hostname with moderate SANS
    with CertMonitor(
        "www.cisco.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    ) as monitor:
        cert = monitor.get_cert_info()
        validation_results = monitor.validate(
            validator_args={"subject_alt_names": ["cisco.com"]}
        )
        print("Hostname with few SANS:")
        print(json.dumps(cert, indent=2))
        print("Validation Results 1:")
        print(validation_results)

        # Validate the certificate with additional arguments for validators
        validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
        validation_results = monitor.validate(validator_args)
        print("Validation Results 2:")
        print(validation_results)
        # print(json.dumps(validation_results, indent=2))

    # Test with another hosthame with no SANS
    with CertMonitor(
        "demo.nautobot.com",
        enabled_validators=["hostname", "expiration", "subject_alt_names"],
    ) as monitor:
        cert = monitor.get_cert_info()
        validation_results = monitor.validate(
            validator_args={"subject_alt_names": ["demo.nautobot.com"]}
        )
        print("Hostname with no SANS:")
        print(json.dumps(cert, indent=2))
        print("Validation Results 1:")
        print(validation_results)

        # Validate the certificate with additional arguments for validators
        validator_args = {"subject_alt_names": ["example.com", "www.example.com"]}
        validation_results = monitor.validate(validator_args)
        print("Validation Results 2:")
        # print(json.dumps(validation_results, indent=2))
        print(validation_results)
