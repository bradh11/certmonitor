from .base import BaseValidator
import ipaddress


class SubjectAltNamesValidator(BaseValidator):
    """A validator for checking the Subject Alternative Names (SANs) in an SSL certificate.

    This validator checks both DNS and IP Address SANs.

    Attributes:
        name (str): The name of the validator.
    """

    name = "subject_alt_names"

    def validate(self, cert, host, port, alternate_names=None):
        """Validates the SANs in the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname or IP to validate against the SANs.
            port (int): The port number.
            alternate_names (list, optional): A list of alternate names to validate against the SANs.

        Returns:
            dict: A dictionary containing the validation results, including whether the SANs are valid,
                  the SANs themselves, the count of SANs, and any warnings or reasons for validation failure.
        """
        if "subjectAltName" not in cert:
            return {
                "is_valid": False,
                "reason": "Certificate does not contain a Subject Alternative Name extension",
                "sans": None,
                "count": 0,
            }

        sans = cert["subjectAltName"]
        dns_sans = sans.get("DNS", [])
        ip_sans = sans.get("IP Address", [])

        result = {
            "is_valid": True,
            "sans": {"DNS": dns_sans, "IP Address": ip_sans},
            "count": len(dns_sans) + len(ip_sans),
            "contains_host": {},
            "contains_alternate": {},
            "warnings": [],
        }

        # Check if the host is in the SANs
        is_valid, reason = self._check_name_in_sans_with_reason(host, dns_sans, ip_sans)
        result["contains_host"] = {
            "name": host,
            "is_valid": is_valid,
            "reason": reason,
        }

        # Check for alternate names if provided
        if alternate_names:
            contains_alternate = {}
            for alternate_name in alternate_names:
                alt_is_valid, alt_reason = self._check_name_in_sans_with_reason(
                    alternate_name, dns_sans, ip_sans
                )
                contains_alternate[alternate_name] = {
                    "name": alternate_name,
                    "is_valid": alt_is_valid,
                    "reason": alt_reason,
                }
            result["contains_alternate"] = contains_alternate

        # Additional checks and warnings
        if not dns_sans and not ip_sans:
            result["warnings"].append(
                "Certificate does not contain any DNS or IP Address SANs"
            )

        if result["count"] > 100:
            result["warnings"].append(
                f"Certificate contains an unusually high number of SANs ({result['count']})"
            )

        if not result["contains_host"]["is_valid"]:
            result["warnings"].append(
                f"The hostname/IP {host} is not included in the SANs: {result['contains_host']['reason']}"
            )

        for alt_name, alt_validation in result["contains_alternate"].items():
            if not alt_validation["is_valid"]:
                result["warnings"].append(
                    f"The alternate name {alt_validation['name']} is not included in the SANs: {alt_validation['reason']}"
                )

        return result

    def _check_name_in_sans_with_reason(self, name, dns_sans, ip_sans):
        """Checks if the given name is present in the SANs and provides a reason.

        Args:
            name (str): The name to check.
            dns_sans (list): The list of DNS SANs.
            ip_sans (list): The list of IP Address SANs.

        Returns:
            tuple: A tuple containing a boolean indicating if the name is present in the SANs,
                   and a reason string.
        """
        # Check if the name is an IP address
        try:
            ip = ipaddress.ip_address(name)
            if str(ip) in ip_sans:
                return True, f"Exact match for IP {name} found in IP Address SANs"
            return False, f"No match found for IP {name} in IP Address SANs"
        except ValueError:
            # Not an IP address, check DNS SANs
            if name in dns_sans:
                return True, f"Exact match for {name} found in DNS SANs"
            for san in dns_sans:
                if self._matches_wildcard(name, san):
                    return True, f"{name} matches wildcard SAN {san}"
            return False, f"No match found for {name} in DNS SANs"

    def _matches_wildcard(self, hostname, pattern):
        """Checks if the given hostname matches a wildcard pattern.

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
