# core.py

import ipaddress
import logging
import os
import socket
import ssl
import tempfile
from typing import Any, Dict, Optional, Union

from certmonitor import certinfo

from certmonitor import config
from certmonitor.cipher_algorithms import parse_cipher_suite
from certmonitor.error_handlers import ErrorHandler
from certmonitor.protocol_handlers.ssh_handler import SSHHandler
from certmonitor.protocol_handlers.ssl_handler import SSLHandler
from certmonitor.validators import VALIDATORS


class CertMonitor:
    """Class for monitoring and retrieving certificate details from a given host."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        enabled_validators: list = config.DEFAULT_VALIDATORS,
    ):
        """Initialize the CertMonitor with the specified host and port."""
        self.host = host
        self.port = port
        self.is_ip = self._is_ip_address(host)
        self.der = None
        self.pem = None
        self.cert_info = None
        self.cert_data = {}
        self.public_key_der = None
        self.public_key_pem = None
        self.validators = VALIDATORS
        self.enabled_validators = enabled_validators or config.ENABLED_VALIDATORS
        self.error_handler = ErrorHandler()
        self.handler = None
        self.protocol = None
        self.connected = False

    def __enter__(self):
        """Enter the runtime context related to this object."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Exit the runtime context related to this object."""
        self.close()

    def connect(self) -> Optional[Dict[str, Any]]:
        """Establishes a connection to the host if not already connected."""
        if self.connected:
            logging.debug("Already connected, skipping connection attempt")
            return None

        self.protocol = self.detect_protocol()
        if isinstance(self.protocol, dict) and "error" in self.protocol:
            return self.protocol

        if self.protocol == "ssl":
            self.handler = SSLHandler(self.host, self.port, self.error_handler)
        elif self.protocol == "ssh":
            self.handler = SSHHandler(self.host, self.port, self.error_handler)
        else:
            return self.error_handler.handle_error(
                "ProtocolError",
                f"Unsupported protocol: {self.protocol}",
                self.host,
                self.port,
            )

        connection_result = self.handler.connect()
        if connection_result is not None:  # This means there was an error
            return connection_result

        self.connected = True
        logging.debug(f"Successfully connected to {self.host}:{self.port}")
        return None

    def close(self):
        """Close the connection and reset the handler."""
        if self.handler:
            self.handler.close()
        self.handler = None

    def detect_protocol(self):
        """Detect the protocol used by the host."""
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                sock.setblocking(False)
                try:
                    data = sock.recv(4, socket.MSG_PEEK)
                    if data.startswith(b"SSH-"):
                        return "ssh"
                    elif data[0] in [22, 128, 160]:  # Common first bytes for SSL/TLS
                        return "ssl"
                    else:
                        return self.error_handler.handle_error(
                            "ProtocolDetectionError",
                            f"Unable to determine protocol. First bytes: {data.hex()}",
                            self.host,
                            self.port,
                        )
                except socket.error:
                    # If no data is received, assume it's SSL
                    return "ssl"
                finally:
                    sock.setblocking(True)
        except Exception as e:
            return self.error_handler.handle_error(
                "ConnectionError", str(e), self.host, self.port
            )

    def _ensure_connection(self):
        """Ensures that a valid connection is established."""
        if not self.connected:
            connect_result = self.connect()
            if connect_result is not None:  # This means there was an error
                return connect_result
        else:
            try:
                self.handler.check_connection()
            except ConnectionError:
                logging.warning("Connection lost, attempting to reconnect")
                self.connected = False
                connect_result = self.connect()
                if connect_result is not None:  # This means there was an error
                    return connect_result

        return None  # No error, connection is established

    def _is_ip_address(self, host: str) -> bool:
        """Check if the provided host is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _fetch_raw_cert(self) -> Dict[str, Any]:
        """Fetches the raw certificate from the connected host."""
        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        cert_data = self.handler.fetch_raw_cert()

        if isinstance(cert_data, dict) and "error" in cert_data:
            return cert_data

        cert_info = cert_data["cert_info"]
        self.der = cert_data["der"]
        self.pem = cert_data["pem"]
        self.public_key_info = {}

        if not cert_info:
            # If getpeercert() returns an empty dict, we'll parse the cert ourselves
            cert_data["cert_info"] = self._parse_pem_cert(self.pem)

        if self.der:
            try:
                # parse_public_key_info expects DER bytes and returns e.g.
                # {"algorithm": "rsaEncryption", "size": 2048, "curve": None}
                pubkey = certinfo.parse_public_key_info(self.der)
                cert_data["public_key_info"] = pubkey
                self.public_key_info = pubkey

                # Extract public key in DER and PEM formats
                self.public_key_der = certinfo.extract_public_key_der(self.der)
                self.public_key_pem = certinfo.extract_public_key_pem(self.der)

                # Add public keys to cert_data
                cert_data["public_key_der"] = self.public_key_der
                cert_data["public_key_pem"] = self.public_key_pem

            except Exception as e:
                logging.error(f"Unable to parse public key info: {e}")
                # If you want, store a partial or error object here instead
                cert_data["public_key_info"] = {
                    "error": f"Failed to parse public key info: {e}"
                }
                self.public_key_der = None
                self.public_key_pem = None
                cert_data["public_key_der"] = None
                cert_data["public_key_pem"] = None
        else:
            # If there's no DER, we can't parse the public key
            cert_data["public_key_info"] = {"error": "DER bytes not available"}
            self.public_key_der = None
            self.public_key_pem = None
            cert_data["public_key_der"] = None
            cert_data["public_key_pem"] = None

        self.cert_data = cert_data
        return cert_data

    def _fetch_raw_cipher(self) -> Union[tuple, Dict[str, Any]]:
        """Fetch the raw cipher information."""
        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "Cipher information is only available for SSL/TLS connections",
                self.host,
                self.port,
            )
        return self.handler.fetch_raw_cipher()

    def _parse_pem_cert(self, pem_cert: str) -> dict:
        """Parse a PEM formatted certificate to extract relevant details."""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(pem_cert)
            temp_file.flush()
            temp_file_path = temp_file.name

        try:
            cert_details = ssl._ssl._test_decode_cert(temp_file_path)
        finally:
            os.remove(temp_file_path)

        return cert_details

    def _to_structured_dict(self, data) -> dict:
        """Convert the certificate data into a structured dictionary format.

        Args:
            data (dict): The certificate data.

        Returns:
            dict: A dictionary containing the structured certificate data.
        """

        def _handle_duplicate_keys(data):
            result = {}
            for item in data:
                if isinstance(item, tuple) and len(item) == 2:
                    key, value = item
                    if key in result:
                        if not isinstance(result[key], list):
                            result[key] = [result[key]]
                        result[key].append(self._to_structured_dict(value))
                    else:
                        result[key] = self._to_structured_dict(value)
            return result

        if isinstance(data, (tuple, list)):
            if all(isinstance(item, tuple) and len(item) == 2 for item in data):
                return _handle_duplicate_keys(data)
            return [self._to_structured_dict(item) for item in data]
        elif isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in ["subject", "issuer"]:
                    result[key] = _handle_duplicate_keys(
                        [item for sublist in value for item in sublist]
                    )
                else:
                    result[key] = self._to_structured_dict(value)
            return result
        else:
            return data

    def get_cert_info(self) -> Dict[str, Any]:
        """Retrieves and structures the certificate details."""
        if not self.cert_info:
            try:
                connection_result = self._ensure_connection()
                if connection_result is not None:  # Connection failed
                    return connection_result

                cert_data = self._fetch_raw_cert()

                if isinstance(cert_data, dict) and "error" in cert_data:
                    logging.error(f"Error in fetching raw certificate: {cert_data}")
                    return cert_data

                # The _fetch_raw_cert already sets self.cert_data, self.public_key_der, self.public_key_pem
                # We just need to structure the cert_info part
                self.cert_info = self._to_structured_dict(cert_data["cert_info"])
                # Update the cert_data with the structured version
                if not hasattr(self, "cert_data") or not self.cert_data:
                    self.cert_data = {}
                self.cert_data["cert_info"] = self.cert_info
                logging.debug("Certificate info retrieved and structured")
            except Exception as e:
                logging.error(f"Error while getting certificate info: {e}")
                return self.error_handler.handle_error(
                    "UnknownError", str(e), self.host, self.port
                )

        return self.cert_info

    def get_raw_der(self) -> Union[bytes, Dict[str, Any]]:
        """Return the raw DER format of the certificate."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "DER format is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.der is None:
            cert_data = self.handler.fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data
            self.der = cert_data.get("der")

        return self.der

    def get_raw_pem(self) -> Union[str, Dict[str, Any]]:
        """Return the raw PEM format of the certificate."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "PEM format is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.pem is None:
            cert_data = self.handler.fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data
            self.pem = cert_data.get("pem")

        return self.pem

    def get_public_key_der(self) -> Union[bytes, Dict[str, Any], None]:
        """Return the public key in DER format."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "Public key extraction is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.public_key_der is None:
            # Trigger certificate fetching which will also extract public keys
            cert_data = self._fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data

        return self.public_key_der

    def get_public_key_pem(self) -> Union[str, Dict[str, Any], None]:
        """Return the public key in PEM format."""
        if self.protocol != "ssl":
            return self.error_handler.handle_error(
                "ProtocolError",
                "Public key extraction is only available for SSL/TLS connections",
                self.host,
                self.port,
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.public_key_pem is None:
            # Trigger certificate fetching which will also extract public keys
            cert_data = self._fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data

        return self.public_key_pem

    def get_cipher_info(self) -> dict:
        """Retrieve and structure the cipher information of the SSL/TLS connection."""
        raw_cipher = self._fetch_raw_cipher()

        # Check if raw_cipher is an error response
        if isinstance(raw_cipher, dict) and "error" in raw_cipher:
            return raw_cipher

        # If raw_cipher is not an error, it should be a tuple of 3 elements
        if not isinstance(raw_cipher, tuple) or len(raw_cipher) != 3:
            return self.error_handler.handle_error(
                "CipherInfoError", "Unexpected cipher info format", self.host, self.port
            )

        cipher_suite, protocol_version, key_bit_length = raw_cipher
        parsed_cipher = parse_cipher_suite(cipher_suite)

        result = {
            "cipher_suite": {
                "name": cipher_suite,
                "encryption_algorithm": parsed_cipher["encryption"],
                "message_authentication_code": parsed_cipher["mac"],
            },
            "protocol_version": protocol_version,
            "key_bit_length": key_bit_length,
        }

        if protocol_version == "TLSv1.3":
            result["cipher_suite"]["key_exchange_algorithm"] = (
                "Not applicable (TLS 1.3 uses ephemeral key exchange by default)"
            )
        else:
            result["cipher_suite"]["key_exchange_algorithm"] = parsed_cipher[
                "key_exchange"
            ]

        return result

    def validate(self, validator_args=None) -> dict:
        """
        Validates the target host by running all enabled validators.

        This method:
        1. Checks if all requested validators are implemented.
        2. Separates validators into cert-based and cipher-based groups.
        3. Fetches cert_info and cipher_info as needed.
        4. Runs each validator with the appropriate arguments.
        5. Returns a dictionary of validation results.

        Args:
            validator_args (dict, optional): Additional arguments for specific validators.
                Example:
                {
                    "subject_alt_names": ["example.com", "test.com"]
                }

        Returns:
            dict: A dictionary keyed by validator name, each value being the result of that validator.

        Example:
            results = monitor.validate()
            print(results["expiration"])      # Output for expiration validator
            print(results["weak_cipher"])     # Output for weak cipher validator
        """
        results = {}

        # Check for unknown validators
        for requested_validator in self.enabled_validators:
            if requested_validator not in self.validators:
                results[requested_validator] = {
                    "is_valid": False,
                    "reason": f"Validator '{requested_validator}' is not implemented.",
                }

        cert_validators = [
            validator
            for name, validator in self.validators.items()
            if name in self.enabled_validators
            and getattr(validator, "validator_type", "cert") == "cert"
            and name not in results  # exclude already marked unknown validators
        ]

        cipher_validators = [
            validator
            for name, validator in self.validators.items()
            if name in self.enabled_validators
            and getattr(validator, "validator_type", "cert") == "cipher"
            and name not in results
        ]

        # Certificate-based validations
        if cert_validators:
            cert_data = getattr(self, "cert_data", None)
            if not cert_data or (isinstance(cert_data, dict) and "error" in cert_data):
                error_reason = (
                    cert_data["error"]
                    if isinstance(cert_data, dict) and "error" in cert_data
                    else "Certificate data is missing due to a connection or retrieval error."
                )
                for validator in cert_validators:
                    results[validator.name] = {
                        "is_valid": False,
                        "reason": f"Certificate-based validation could not be performed: {error_reason}",
                    }
            else:
                for validator in cert_validators:
                    args = [cert_data, self.host, self.port]
                    # Pass additional arguments if any
                    if validator_args and validator.name in validator_args:
                        if validator.name == "subject_alt_names":
                            args.append(validator_args[validator.name])
                        else:
                            args.extend(validator_args[validator.name])

                    results[validator.name] = validator.validate(*args)

        # Cipher-based validations
        if cipher_validators:
            cipher_info = self.get_cipher_info()
            if isinstance(cipher_info, dict) and "error" in cipher_info:
                logging.error(
                    "Skipping cipher-based validations due to cipher info retrieval error."
                )
            else:
                for validator in cipher_validators:
                    args = [cipher_info, self.host, self.port]
                    # Pass additional arguments if any
                    if validator_args and validator.name in validator_args:
                        args.extend(validator_args[validator.name])

                    results[validator.name] = validator.validate(*args)

        return results
