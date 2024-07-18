from .base import BaseValidator


class HostnameValidator(BaseValidator):
    """
    A validator for checking the hostname in an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name = "hostname"

    def validate(self, cert, host, port):
        """
        Validates the hostname against the Subject Alternative Names (SANs) in the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname to validate.
            port (int): The port number.

        Returns:
            dict: A dictionary containing the validation results, including whether the hostname is valid,
                  the reason for validation failure, and the alternative names (SANs) in the certificate.
        """
        if "subjectAltName" not in cert:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain a Subject Alternative Name extension",
            }

        sans = cert["subjectAltName"]

        # Ensure sans is a list of DNS names
        if isinstance(sans, dict):
            dns_names = sans.get("DNS", [])
            if isinstance(dns_names, str):
                dns_names = [dns_names]
        else:
            dns_names = [item[1] for item in sans if item[0] == "DNS"]

        if not dns_names:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain any DNS SANs",
                "alt_names": [],
            }

        # Check if the hostname matches any of the DNS names
        if self._matches_hostname(host, dns_names):
            return {"is_valid": True, "matched_name": host, "alt_names": dns_names}

        # If no match found, check for wildcard certificates
        for name in dns_names:
            if self._matches_wildcard(host, name):
                return {"is_valid": True, "matched_name": name, "alt_names": dns_names}

        return {
            "is_valid": False,
            "reason": f"Hostname {host} doesn't match any of the certificate's subject alternative names",
            "alt_names": dns_names,
        }

    def _matches_hostname(self, hostname, cert_names):
        """
        Checks if the hostname matches any of the provided certificate names.

        Args:
            hostname (str): The hostname to check.
            cert_names (list): The list of certificate names.

        Returns:
            bool: True if the hostname matches any of the certificate names, False otherwise.
        """
        return hostname.lower() in (name.lower() for name in cert_names)

    def _matches_wildcard(self, hostname, pattern):
        """
        Checks if the hostname matches a wildcard pattern.

        Args:
            hostname (str): The hostname to check.
            pattern (str): The wildcard pattern to match against.

        Returns:
            bool: True if the hostname matches the wildcard pattern, False otherwise.
        """
        if not pattern.startswith("*."):
            return False

        host_parts = hostname.split(".")
        pattern_parts = pattern[2:].split(".")  # Remove '*.' and split

        if len(host_parts) != len(pattern_parts) + 1:
            return False

        return host_parts[1:] == pattern_parts
