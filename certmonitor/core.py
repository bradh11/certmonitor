# core.py

from datetime import datetime, timezone
import ipaddress
import re
import logging
import os
import socket
import ssl
import tempfile
import warnings
from typing import Any, cast
from collections.abc import Callable, Mapping
from pathlib import Path

from certmonitor import certinfo, config
from certmonitor.cipher_algorithms import parse_cipher_suite
from certmonitor.error_handlers import ErrorHandler
from certmonitor.protocol_handlers.base import BaseProtocolHandler
from certmonitor.protocol_handlers.ssh_handler import SSHHandler
from certmonitor.protocol_handlers.ssl_handler import SSLHandler
from certmonitor.validators import VALIDATORS


class CertMonitor:
    """Class for monitoring and retrieving certificate details from a given host."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        enabled_validators: list[str] | None = None,
        *,
        connection_host: str | None = None,
        server_hostname: str | None = None,
        timeout: float = 10,
        cafile: str | None = None,
        capath: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
    ):
        """Initialize a monitor for a host without opening a connection.

        Use a context manager to connect and close automatically. Retrieval and
        validation methods can also connect lazily. By default, validation checks
        expiration, SAN-based hostname identity, and trust through a separate
        verified handshake. Collection itself is permissive.

        Args:
            host: The identity the certificate is checked against. Also the
                default TCP destination and TLS SNI name.
            port: Target TCP port. Defaults to 443.
            enabled_validators: Names to run. `None` uses the environment-backed
                configuration; an empty list disables all checks.
            connection_host: Override the TCP destination, such as a backend IP.
            server_hostname: Override the TLS SNI name sent to the server.
            timeout: Positive timeout in seconds for each network operation,
                including each connection attempt made while collecting the
                certificate. This is not a whole-scan deadline; platform DNS
                resolution cannot be interrupted by this timeout.
            cafile: PEM CA bundle for the separate verified trust handshake.
            capath: OpenSSL-compatible CA directory for the verified trust handshake.
            client_cert: Client certificate chain file for mutual TLS.
            client_key: Separate client private-key file, if needed.

        Raises:
            ValueError: If `timeout` is not positive.

        Example:
            ```python
            with CertMonitor("example.com") as monitor:
                print(monitor.validate())
            ```
        """
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.connection_host = connection_host or host
        self.server_hostname = server_hostname or host
        self.timeout = timeout
        self.cafile, self.capath = cafile, capath
        self.client_cert, self.client_key = client_cert, client_key
        self.snapshot_at: str | None = None
        self._verify_contexts: dict[bool, ssl.SSLContext] = {}
        self._trust_verdict: tuple[bytes, dict[str, Any]] | None = None
        self._certificate_source: dict[str, Any] | None = None
        self._offline_bytes: bytes | None = None
        self.host = host
        self.port = port
        self.is_ip = self._is_ip_address(host)
        self.der: bytes | None = None
        self.pem: str | None = None
        self.cert_info = None
        self.cert_data: dict[str, Any] = {}
        self.public_key_der = None
        self.public_key_pem = None
        self.validators = VALIDATORS
        self.enabled_validators = (
            enabled_validators
            if enabled_validators is not None
            else config.ENABLED_VALIDATORS
        )
        self.error_handler = ErrorHandler()
        self.handler: BaseProtocolHandler | None = None
        self.protocol: str | None = None
        self.connected = False

    @classmethod
    def from_file(
        cls,
        path: str | os.PathLike[str],
        *,
        host: str | None = None,
        port: int = 443,
        enabled_validators: list[str] | None = None,
    ) -> "CertMonitor":
        """Build a monitor from a certificate file instead of a connection.

        The file may be PEM (a single certificate or a chain, leaf first) or
        DER. Everything that only needs certificate data works as it does for
        a connected monitor: `get_cert_info()`, the public key helpers,
        `validate()`, and `refresh()`, which re-reads the file. Checks that
        need a live connection (`tls_version`, `weak_cipher`, `root_certificate`,
        `pq_key_exchange`) report `status: unsupported` with a reason.

        Args:
            path: Path to the PEM or DER file.
            host: The identity the certificate should be valid for, used by
                `hostname` and `subject_alt_names`. Without it those two
                checks report `unsupported` rather than guessing.
            port: Port to report alongside the host. Defaults to 443.
            enabled_validators: Names to run. `None` uses the environment-backed
                configuration.

        Example:
            ```python
            with CertMonitor.from_file("service.pem", host="service.example.com") as monitor:
                print(monitor.validate()["expiration"])
            ```
        """
        monitor = cls(host or "", port, enabled_validators)
        monitor._certificate_source = {"type": "file", "path": os.fspath(path)}
        monitor.protocol = "ssl"
        return monitor

    @classmethod
    def from_bytes(
        cls,
        data: bytes | str,
        *,
        host: str | None = None,
        port: int = 443,
        enabled_validators: list[str] | None = None,
    ) -> "CertMonitor":
        """Build a monitor from PEM text or DER bytes already in memory.

        Behaves like `from_file()`; use it for certificates fetched from an
        API, a secrets store, or a database. `refresh()` re-parses the same
        bytes.

        Args:
            data: PEM text (str or bytes) or DER bytes.
            host: The identity the certificate should be valid for.
            port: Port to report alongside the host. Defaults to 443.
            enabled_validators: Names to run. `None` uses the environment-backed
                configuration.
        """
        monitor = cls(host or "", port, enabled_validators)
        monitor._offline_bytes = data.encode() if isinstance(data, str) else bytes(data)
        monitor._certificate_source = {"type": "bytes"}
        monitor.protocol = "ssl"
        return monitor

    @property
    def offline(self) -> bool:
        """True when the certificate comes from a file or bytes, not a connection."""
        return self._certificate_source is not None

    _PEM_BLOCK = re.compile(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
    )

    def _load_offline_certificate(self) -> dict[str, Any]:
        """Read and decode the offline certificate into the collector's shape."""
        assert self._certificate_source is not None
        try:
            if self._certificate_source["type"] == "file":
                data = Path(self._certificate_source["path"]).read_bytes()
            else:
                data = self._offline_bytes or b""
            blocks = self._PEM_BLOCK.findall(data)
            if blocks:
                pems = [block.decode("ascii") + "\n" for block in blocks]
                chain_der = [ssl.PEM_cert_to_DER_cert(pem) for pem in pems]
            elif data:
                chain_der = [bytes(data)]
                pems = [ssl.DER_cert_to_PEM_cert(chain_der[0])]
            else:
                raise ValueError("no certificate data")
            cert_info = self._parse_pem_cert(pems[0])
            if not cert_info:
                raise ValueError("data is not a PEM or DER X.509 certificate")
        except Exception as exc:  # noqa: BLE001
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "CertificateError",
                    f"Could not load certificate: {exc}",
                    self.host,
                    self.port,
                ),
            )
        return {
            "cert_info": cert_info,
            "der": chain_der[0],
            "pem": pems[0],
            "chain_der": chain_der,
            "chain_error": None,
        }

    def __enter__(self) -> "CertMonitor":
        """Enter the runtime context related to this object."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Exit the runtime context related to this object."""
        self.close()

    def connect(self) -> dict[str, Any] | None:
        """Establishes a connection to the host if not already connected."""
        if self.connected:
            logging.debug("Already connected, skipping connection attempt")
            return None
        if self.offline:
            self.connected = True
            return None

        protocol_result = self.detect_protocol()
        if isinstance(protocol_result, dict) and "error" in protocol_result:
            return protocol_result

        # If we get here, protocol_result is a string
        self.protocol = cast(str, protocol_result)

        if self.protocol == "ssl":
            self.handler = SSLHandler(
                self.connection_host, self.port, self.error_handler
            )
            self.handler.server_hostname = self.server_hostname
            self.handler.timeout = self.timeout
            self.handler.client_cert = self.client_cert
            self.handler.client_key = self.client_key
        elif self.protocol == "ssh":
            self.handler = SSHHandler(
                self.connection_host, self.port, self.error_handler
            )
            self.handler.timeout = self.timeout
        else:
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ProtocolError",
                    f"Unsupported protocol: {self.protocol}",
                    self.host,
                    self.port,
                ),
            )

        connection_result = self.handler.connect()
        if connection_result is not None:  # This means there was an error
            return connection_result

        self.connected = True
        logging.debug(f"Successfully connected to {self.host}:{self.port}")
        return None

    def close(self) -> None:
        """Close the connection, retaining the last snapshot for inspection."""
        try:
            if self.handler:
                self.handler.close()
        finally:
            self.handler = None
            self.connected = False

    def _clear_snapshot(self) -> None:
        """Discard collected data before refresh or a new connection."""
        self.cert_data = {}
        self.cert_info = None
        self.der = self.pem = None
        self.public_key_der = self.public_key_pem = None
        self.public_key_info = None
        self.snapshot_at = None
        self._trust_verdict = None

    def refresh(self) -> dict[str, Any]:
        """Close the old connection and collect a new timestamped snapshot."""
        self.close()
        self._clear_snapshot()
        return self.get_cert_info()

    def detect_protocol(self) -> str | dict[str, Any]:
        """Detect the protocol used by the host."""
        try:
            with socket.create_connection(
                (self.connection_host, self.port), timeout=self.timeout
            ) as sock:
                sock.setblocking(False)
                try:
                    data = sock.recv(4, socket.MSG_PEEK)
                    if data.startswith(b"SSH-"):
                        return "ssh"
                    elif data and data[0] in [
                        22,
                        128,
                        160,
                    ]:  # Common first bytes for SSL/TLS
                        return "ssl"
                    else:
                        return cast(
                            dict[str, Any],
                            self.error_handler.handle_error(
                                "ProtocolDetectionError",
                                f"Unable to determine protocol. First bytes: {data.hex()}",
                                self.host,
                                self.port,
                            ),
                        )
                except OSError:
                    # If no data is received, assume it's SSL
                    return "ssl"
                finally:
                    sock.setblocking(True)
        except Exception as e:
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ConnectionError", str(e), self.host, self.port
                ),
            )

    def _ensure_connection(self) -> dict[str, Any] | None:
        """Ensures that a valid connection is established."""
        if self.offline:
            self.connected = True
            return None
        if not self.connected:
            connect_result = self.connect()
            if connect_result is not None:  # This means there was an error
                return connect_result
        else:
            try:
                if self.handler is None:
                    # Handler is None, need to reconnect
                    self.connected = False
                    connect_result = self.connect()
                    if connect_result is not None:
                        return connect_result
                else:
                    # Handler exists, check if connection is still valid
                    # Use hasattr to check if check_connection method exists
                    if hasattr(self.handler, "check_connection"):
                        # Call check_connection and let any exceptions bubble up
                        if cast(Any, self.handler).check_connection() is False:
                            raise ConnectionError("Connection is closed")
                    # If no exception was raised, connection is still valid
            except ConnectionError:
                logging.warning("Connection lost, attempting to reconnect")
                self.close()
                self._clear_snapshot()
                connect_result = self.connect()
                if connect_result is not None:  # This means there was an error
                    return connect_result

        return None  # No error, connection is established

    _OFFLINE_REASON = (
        "{what} requires a live connection; this certificate was loaded from a file."
    )

    def _offline_error(self, what: str) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self.error_handler.handle_error(
                "OfflineSource",
                self._OFFLINE_REASON.format(what=what),
                self.host,
                self.port,
            ),
        )

    def _is_ip_address(self, host: str) -> bool:
        """Check if the provided host is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _fetch_raw_cert(self) -> dict[str, Any]:
        """Fetches the raw certificate from the connected host."""
        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.offline:
            cert_data = self._load_offline_certificate()
        elif self.handler is None:
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ConnectionError",
                    "Handler is not initialized",
                    self.host,
                    self.port,
                ),
            )
        else:
            cert_data = self.handler.fetch_raw_cert()

        if isinstance(cert_data, dict) and "error" in cert_data:
            return cert_data

        cert_info = cert_data["cert_info"]
        self.der = cert_data.get("der")  # Use .get() to allow None
        self.pem = cert_data.get("pem")  # Use .get() to allow None

        if not cert_info:
            # If getpeercert() returns an empty dict, we'll parse the cert ourselves
            if self.pem is not None:
                cert_data["cert_info"] = self._parse_pem_cert(self.pem)
            else:
                cert_data["cert_info"] = {}

        if self.der:
            try:
                # parse_public_key_info expects DER bytes and returns e.g.
                # {"algorithm": "rsaEncryption", "size": 2048, "curve": None}
                pubkey = certinfo.parse_public_key_info(self.der)  # type: ignore[attr-defined]
                cert_data["public_key_info"] = pubkey
                self.public_key_info = pubkey

                # Extract public key in DER and PEM formats
                self.public_key_der = certinfo.extract_public_key_der(self.der)  # type: ignore[attr-defined]
                self.public_key_pem = certinfo.extract_public_key_pem(self.der)  # type: ignore[attr-defined]

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

        chain_der = cert_data.get("chain_der")
        if chain_der:
            try:
                cert_data["chain_analysis"] = certinfo.analyze_chain(chain_der)  # type: ignore[attr-defined]
            except Exception as e:  # noqa: BLE001
                logging.error(f"Unable to analyze certificate chain: {e}")
                cert_data["chain_analysis"] = {
                    "error": f"Failed to analyze certificate chain: {e}"
                }
        else:
            cert_data.setdefault("chain_analysis", None)

        # Leaf-only fallback: when the chain could not be retrieved
        # (a chain fetch or parse failure, e.g. an unreachable issuer) but the leaf
        # DER is in hand, analyze just the leaf so leaf-scoped validators
        # (e.g. pq_signature, which needs the leaf's signature algorithm)
        # work on every interpreter instead of inheriting the chain's
        # availability constraints.
        chain_ok = (
            isinstance(cert_data.get("chain_analysis"), dict)
            and "error" not in cert_data["chain_analysis"]
        )
        if not chain_ok and self.der:
            try:
                cert_data["leaf_analysis"] = certinfo.analyze_chain([self.der])  # type: ignore[attr-defined]
            except Exception as e:  # noqa: BLE001
                logging.error(f"Unable to analyze leaf certificate: {e}")
                cert_data["leaf_analysis"] = {
                    "error": f"Failed to analyze leaf certificate: {e}"
                }

        self.snapshot_at = datetime.now(timezone.utc).isoformat()
        cert_data["snapshot_at"] = self.snapshot_at
        source = self._certificate_source
        cert_data["source"] = (
            dict(source)
            if source is not None
            else {"type": "connection", "host": self.connection_host, "port": self.port}
        )
        self.cert_data = cert_data
        return cert_data

    def _fetch_raw_cipher(self) -> tuple[str, str, int] | dict[str, Any]:
        """Fetch the raw cipher information."""
        if self.offline:
            return self._offline_error("Cipher information")
        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.protocol != "ssl":
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ProtocolError",
                    "Cipher information is only available for SSL/TLS connections",
                    self.host,
                    self.port,
                ),
            )

        if self.handler is None:
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ConnectionError",
                    "Handler is not initialized",
                    self.host,
                    self.port,
                ),
            )

        # fetch_raw_cipher is only available on SSL handlers
        if hasattr(self.handler, "fetch_raw_cipher"):
            # We know the handler has fetch_raw_cipher, so we can use Any to bypass type checking
            return cast(
                tuple[str, str, int] | dict[str, Any],
                cast(Any, self.handler).fetch_raw_cipher(),
            )
        else:
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ProtocolError",
                    "fetch_raw_cipher not available for this handler type",
                    self.host,
                    self.port,
                ),
            )

    def _parse_pem_cert(self, pem_cert: str) -> dict[str, Any]:
        """Parse a PEM formatted certificate to extract relevant details."""
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
            temp_file.write(pem_cert)
            temp_file.flush()
            temp_file_path = temp_file.name

        try:
            # Use ssl module's private API with proper error handling
            # This may not be available in all Python versions
            try:
                cert_details = ssl._ssl._test_decode_cert(temp_file_path)  # type: ignore[attr-defined]
            except AttributeError:
                # Fallback: return empty dict if private API is not available
                cert_details = {}
        finally:
            os.remove(temp_file_path)

        # Ensure we return a Dict[str, Any]
        return cast(dict[str, Any], cert_details)

    def _to_structured_dict(self, data: Any) -> Any:
        """Convert the certificate data into a structured dictionary format.

        Args:
            data (dict): The certificate data.

        Returns:
            dict: A dictionary containing the structured certificate data.
        """

        def _handle_duplicate_keys(data: Any) -> dict[str, Any]:
            result: dict[str, Any] = {}
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
                if key in ["subject", "issuer"] and not isinstance(value, dict):
                    result[key] = _handle_duplicate_keys(
                        [item for sublist in value for item in sublist]
                    )
                elif key == "subjectAltName":
                    from .utils.identity import normalize_sans

                    result[key] = normalize_sans(value)
                else:
                    result[key] = self._to_structured_dict(value)
            return result
        else:
            return data

    def get_cert_info(self) -> dict[str, Any]:
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
                return cast(
                    dict[str, Any],
                    self.error_handler.handle_error(
                        "UnknownError", str(e), self.host, self.port
                    ),
                )

        return self.cert_info if self.cert_info is not None else {}

    def get_raw_der(self) -> bytes | dict[str, Any]:
        """Return the raw DER format of the certificate."""
        if self.protocol != "ssl":
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ProtocolError",
                    "DER format is only available for SSL/TLS connections",
                    self.host,
                    self.port,
                ),
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.der is None:
            if self.handler is None:
                return cast(
                    dict[str, Any],
                    self.error_handler.handle_error(
                        "ConnectionError",
                        "Handler is not initialized",
                        self.host,
                        self.port,
                    ),
                )

            cert_data = self.handler.fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data
            self.der = cert_data.get("der")

        # Return the DER or empty bytes if None
        return self.der if self.der is not None else b""

    def get_raw_pem(self) -> str | dict[str, Any]:
        """Return the raw PEM format of the certificate."""
        if self.protocol != "ssl":
            return cast(
                dict[str, Any],
                self.error_handler.handle_error(
                    "ProtocolError",
                    "PEM format is only available for SSL/TLS connections",
                    self.host,
                    self.port,
                ),
            )

        connection_result = self._ensure_connection()
        if connection_result is not None:  # Connection failed
            return connection_result

        if self.pem is None:
            if self.handler is None:
                return cast(
                    dict[str, Any],
                    self.error_handler.handle_error(
                        "ConnectionError",
                        "Handler is not initialized",
                        self.host,
                        self.port,
                    ),
                )

            cert_data = self.handler.fetch_raw_cert()
            if isinstance(cert_data, dict) and "error" in cert_data:
                return cert_data
            self.pem = cert_data.get("pem")

        # Return the PEM or empty string if None
        return self.pem if self.pem is not None else ""

    def get_public_key_der(self) -> bytes | dict[str, Any] | None:
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

    def get_public_key_pem(self) -> str | dict[str, Any] | None:
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

    def get_cipher_info(self) -> dict[str, Any]:
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
        parsed_cipher: dict[str, str] = parse_cipher_suite(cipher_suite)

        result: dict[str, Any] = {
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

    def validate(self, validator_args: dict[str, Any] | None = None) -> dict[str, Any]:
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
                    "subject_alt_names": {"alternate_names": ["www.example.com"]}
                }

        Returns:
            dict: A dictionary keyed by validator name, each value being the result of that validator.

        Example:
            with CertMonitor("example.com", enabled_validators=["expiration", "weak_cipher"]) as monitor:
                results = monitor.validate()
                print(results["expiration"])
                print(results["weak_cipher"])
        """
        results: dict[str, Any] = {}

        # Check for unknown validators
        for requested_validator in self.enabled_validators:
            if requested_validator not in self.validators:
                results[requested_validator] = {
                    "is_valid": False,
                    "status": "unsupported",
                    "reason": f"Validator '{requested_validator}' is not implemented.",
                }

        # Active validators: enabled, implemented, and not already flagged
        # unknown above. Order follows the registry.
        active = [
            validator
            for name, validator in self.validators.items()
            if name in self.enabled_validators and name not in results
        ]

        # Each named data source is fetched at most once per call and
        # shared across every validator that requires it (e.g. cipher_info
        # and a future tls_probe).
        source_cache: dict[str, Any] = {}

        def resolve_source(source_name: str) -> Any:
            if source_name not in source_cache:
                source_cache[source_name] = self._fetch_source(
                    source_name, resolve_source
                )
            return source_cache[source_name]

        for validator in active:
            # `requires` is authoritative when a validator declares it as
            # a real tuple; otherwise fall back to the legacy
            # `validator_type` mapping (also what test doubles use).
            requires = getattr(validator, "requires", None)
            if not isinstance(requires, tuple):
                vtype = getattr(validator, "validator_type", "cert")
                requires = ("cipher_info",) if vtype == "cipher" else ("cert_data",)

            resolved: list[Any] = []
            source_error: dict[str, Any] | None = None
            for source_name in requires:
                value = resolve_source(source_name)
                source_error = self._source_error(source_name, value)
                if source_error is not None:
                    break
                resolved.append(value)

            # Uniform rule: if any required source could not be obtained,
            # the validator still appears in the results with a structured
            # error, never silently omitted.
            if source_error is not None:
                results[validator.name] = source_error
                continue

            results[validator.name] = self._invoke_validator(
                validator,
                (*resolved, self.host, self.port),
                validator_args,
            )

        for name, result in results.items():
            result.setdefault(
                "status",
                "error"
                if result.get("error")
                else "fail"
                if not result.get("is_valid")
                else "warn"
                if result.get("warnings")
                else "pass",
            )
            result.setdefault("code", f"{name}.{result['status']}")
        return results

    def _fetch_source(
        self,
        source_name: str,
        resolve: Callable[[str], Any] | None = None,
    ) -> Any:
        """Fetch one named data source for the validator dispatcher.

        Sources are intentionally small and registry-like so new ones
        (e.g. `tls_probe`) are a single `elif` rather than a new
        dispatch branch. Each may return its normal value or a structured
        error dict; `_source_error` decides which. `resolve` is the
        dispatcher's per-call cache, used when one source depends on another
        so a failed fetch is never retried within the same `validate()` call.
        """
        resolve = resolve or self._fetch_source
        if source_name == "cert_data":
            if not self.cert_data:
                info = self.get_cert_info()
                if "error" in info:
                    return info
            return self.cert_data
        if source_name == "verified_trust":
            cert_data = resolve("cert_data")
            collection_error = self._source_error("cert_data", cert_data)
            if collection_error is not None:
                collection_error.setdefault("error", "MissingCertificate")
                collection_error.update(issuer={}, warnings=[])
                return collection_error
            verification = self._verify_trust()
            verification["issuer"] = cert_data.get("cert_info", {}).get("issuer", {})
            verification.setdefault("warnings", [])
            return verification
        if source_name == "cipher_info":
            return self.get_cipher_info()
        if source_name == "tls_probe":
            return self._fetch_tls_probe()
        return {
            "error": "UnknownSource",
            "message": f"No fetcher registered for data source {source_name!r}.",
        }

    def _verify_context(self, legacy: bool) -> ssl.SSLContext:
        """Return a verifying context, built once per monitor and setting.

        The strict context uses the interpreter's defaults (TLS 1.2 or newer,
        modern ciphers). The legacy context mirrors the permissive collector so
        that hosts reachable only with older protocol or cipher settings still
        receive a trust verdict. Both verify the chain against the configured
        or system CA store; only hostname checking is left to the `hostname`
        validator.
        """
        context = self._verify_contexts.get(legacy)
        if context is None:
            context = ssl.create_default_context(cafile=self.cafile, capath=self.capath)
            context.check_hostname = False
            if legacy:
                context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                context.set_ciphers("ALL:@SECLEVEL=0")
            if self.client_cert:
                context.load_cert_chain(self.client_cert, self.client_key)
            self._verify_contexts[legacy] = context
        return context

    def _verified_peer(self, legacy: bool) -> bytes:
        """Complete a verified handshake and return the DER leaf it observed."""
        context = self._verify_context(legacy)
        with socket.create_connection(
            (self.connection_host, self.port), timeout=self.timeout
        ) as sock:
            with context.wrap_socket(
                sock, server_hostname=self.server_hostname
            ) as secure:
                return secure.getpeercert(binary_form=True) or b""

    def _verify_trust(self) -> dict[str, Any]:
        """Verify a separate handshake, requiring the collected leaf to match.

        A strict handshake is tried first. If it cannot be negotiated, or it
        observes a different leaf than the collector, the handshake is retried
        with the collector's legacy protocol and cipher settings so the
        verdict describes the same certificate that was collected.

        The verdict is bound to the collected leaf and reused for later
        `validate()` calls on the same snapshot; `refresh()` collects a new
        leaf and verifies it again.
        """
        if self.offline:
            return {
                "is_valid": False,
                "status": "unsupported",
                "reason": self._OFFLINE_REASON.format(what="Trust verification"),
            }
        if self.protocol != "ssl" or not self.der:
            return {
                "is_valid": False,
                "status": "error",
                "error": "MissingCertificate",
                "reason": "A collected TLS certificate is required for trust verification.",
            }
        if self._trust_verdict is not None and self._trust_verdict[0] == self.der:
            cached = self._trust_verdict[1]
            return {**cached, "warnings": list(cached.get("warnings", []))}
        verdict = self._verify_trust_now()
        if verdict.get("status") != "error":
            self._trust_verdict = (self.der, verdict)
        return {**verdict, "warnings": list(verdict.get("warnings", []))}

    def _verify_trust_now(self) -> dict[str, Any]:
        """Run the verified handshake(s) and return an uncached verdict."""
        assert self.der is not None
        mismatch = False
        last_error: Exception | None = None
        for legacy in (False, True):
            try:
                peer = self._verified_peer(legacy)
            except ssl.SSLCertVerificationError as exc:
                # verify_message is OpenSSL's short explanation ("self-signed
                # certificate"); str(exc) wraps it in library noise.
                message = getattr(exc, "verify_message", None) or str(exc)
                return {
                    "is_valid": False,
                    "status": "fail",
                    "reason": f"Certificate verification failed: {message}",
                    "verify_code": exc.verify_code,
                    "trust_verified": False,
                }
            except (OSError, ValueError) as exc:
                last_error = exc
                continue
            if peer != self.der:
                mismatch = True
                continue
            result: dict[str, Any] = {
                "is_valid": True,
                "status": "pass",
                "trust_verified": True,
                "revocation_status": "not_checked",
                "warnings": [],
            }
            if legacy:
                result["warnings"].append(
                    "Trust was verified using legacy protocol and cipher settings; "
                    "the strict TLS 1.2+ handshake could not confirm the collected certificate."
                )
            return result
        if mismatch:
            return {
                "is_valid": False,
                "status": "error",
                "error": "SnapshotMismatch",
                "reason": "Verification observed a different certificate; refresh and retry.",
            }
        return {
            "is_valid": False,
            "status": "error",
            "error": type(last_error).__name__,
            "reason": str(last_error),
        }

    def _fetch_tls_probe(self) -> dict[str, Any]:
        """Probe the negotiated TLS 1.3 key-exchange group via the Rust probe.

        Skip-for-legacy short-circuit: the *primary* connection has already
        negotiated a TLS version, so if it is below TLS 1.3 there is no PQ
        KEM to find, we return an `n/a` result without opening the
        probe's second TCP connection. Only TLS 1.3 (or an unknown version,
        out of caution) actually triggers the probe. Errors come back as
        the probe's structured `{"result": "error", ...}` dict; this
        never raises.
        """
        if self.offline:
            return {
                "result": "n/a",
                "protocol": "offline",
                "reason": self._OFFLINE_REASON.format(what="The post-quantum probe"),
            }
        # The probe speaks TLS; never run it against non-SSL protocols
        # (e.g. SSH hosts), regardless of validator configuration.
        if self.protocol is not None and self.protocol != "ssl":
            return {
                "result": "n/a",
                "protocol": self.protocol,
                "reason": f"{self.protocol} is not a TLS endpoint",
            }
        version = (
            self.handler.get_protocol_version()
            if self.handler is not None
            and hasattr(self.handler, "get_protocol_version")
            else None
        )
        if version is not None and version not in ("TLSv1.3", "Unknown"):
            return {
                "result": "n/a",
                "protocol": version,
                "reason": f"{version} has no post-quantum key exchange",
            }
        try:
            observation = cast(
                dict[str, Any],
                certinfo.probe_tls_handshake(  # type: ignore[attr-defined]
                    self.connection_host,
                    self.port,
                    int(self.timeout * 1000),
                    server_name=self.server_hostname,
                ),
            )
            observation.update(
                endpoint=f"{self.connection_host}:{self.port}",
                observed_at=datetime.now(timezone.utc).isoformat(),
                offered_groups=[4588, 29, 23],
                handshake_completed=False,
                authenticated=False,
            )
            return observation
        except Exception as exc:  # noqa: BLE001  (never let the probe raise into dispatch)
            return {
                "result": "error",
                "error": "ProbeError",
                "message": f"TLS probe failed: {exc}",
            }

    def _source_error(self, source_name: str, value: Any) -> dict[str, Any] | None:
        """Return a structured error result if `value` is unusable.

        Returns `None` when the source is good. The messages preserve the
        historical wording so existing callers and tests keep working.
        """
        if source_name == "cert_data":
            if not value or (isinstance(value, dict) and "error" in value):
                reason = (
                    value["error"]
                    if isinstance(value, dict) and "error" in value
                    else "Certificate data is missing due to a connection or retrieval error."
                )
                result = {
                    "is_valid": False,
                    "status": "error",
                    "reason": f"Certificate-based validation could not be performed: {reason}",
                }
                if isinstance(value, dict) and "error" in value:
                    result["error"] = value["error"]
                return result
            return None
        if source_name in ("tls_probe", "verified_trust"):
            # The probe always returns a usable result dict (group / n/a /
            # error); the consuming validator interprets it, so it is never
            # a "source failure" that skips the validator.
            return None
        if isinstance(value, dict) and value.get("error") == "OfflineSource":
            return {
                "is_valid": False,
                "status": "unsupported",
                "reason": value["message"],
            }
        if isinstance(value, dict) and "error" in value:
            label = "Cipher" if source_name == "cipher_info" else source_name
            return {
                "is_valid": False,
                "status": "error",
                "error": value["error"],
                "reason": f"{label}-based validation could not be performed: {value['error']}",
            }
        return None

    def _invoke_validator(
        self,
        validator: Any,
        framework_args: tuple[Any, ...],
        validator_args: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Resolve user kwargs from `validator_args` and call `validator.validate`.

        Looks up the validator's cached `_user_param_names` (built at class
        definition time by `BaseCertValidator.__init_subclass__`) and projects
        the per-validator entry of `validator_args` onto them. Returns a
        structured error dict if the user passed unknown keys; otherwise calls
        the validator and returns its result.
        """
        raw = (validator_args or {}).get(validator.name)
        kwargs: Mapping[str, Any]

        if raw is None:
            kwargs = {}
        elif isinstance(raw, dict):
            kwargs = raw
        else:
            # Backwards-compatibility shim: pre-#18, `subject_alt_names` accepted
            # a bare list of alternate names. Map a bare list to the validator's
            # single user param if (and only if) it has exactly one. Emit a
            # `DeprecationWarning` so callers can migrate to the named form.
            user_param_names: frozenset[str] = getattr(
                validator, "_user_param_names", frozenset()
            )
            if isinstance(raw, list) and len(user_param_names) == 1:
                only_param = next(iter(user_param_names))
                warnings.warn(
                    (
                        f"Passing a bare list to validator_args[{validator.name!r}] "
                        f"is deprecated; use {{'{validator.name}': "
                        f"{{'{only_param}': [...]}}}} instead."
                    ),
                    DeprecationWarning,
                    stacklevel=3,
                )
                kwargs = {only_param: raw}
            else:
                return {
                    "is_valid": False,
                    "status": "error",
                    "error": "InvalidValidatorArgs",
                    "reason": (
                        f"Invalid args for validator {validator.name!r}: "
                        f"expected a dict of keyword arguments, got {type(raw).__name__}."
                    ),
                }

        user_param_names = getattr(validator, "_user_param_names", frozenset())
        unknown = set(kwargs) - set(user_param_names)
        if unknown:
            return {
                "is_valid": False,
                "status": "error",
                "error": "UnknownValidatorArgs",
                "reason": (
                    f"Unknown args for validator {validator.name!r}: "
                    f"{sorted(unknown)}. Accepted args: {sorted(user_param_names)}."
                ),
            }

        try:
            # Validators may return any Mapping, including a read-only mapping
            # or a shared dict. Enrich our own copy, never their retained result.
            return dict(validator.validate(*framework_args, **kwargs))
        except (TypeError, ValueError) as exc:
            # Validators raise these for arguments they cannot accept; the
            # exception class is kept so callers can tell the two apart.
            return {
                "is_valid": False,
                "status": "error",
                "error": type(exc).__name__,
                "reason": f"Validator {validator.name!r} rejected args: {exc}",
            }

    def get_enabled_validators(self) -> list[str]:
        """
        Get the list of validators enabled for this CertMonitor instance.

        Returns:
            List[str]: A list of enabled validator names for this instance.
        """
        return (
            self.enabled_validators.copy()
        )  # Return a copy to prevent external modification

    def list_validators(self) -> list[str]:
        """
        Get a list of all available validators that can be used.

        Returns:
            List[str]: A list of all registered validator names.
        """
        from .validators import list_validators as _list_validators

        return _list_validators()

    def describe_validators(self) -> dict[str, dict[str, Any]]:
        """Describe every registered validator and the user args it accepts.

        Reads each validator's cached `_user_params` (built by
        `BaseCertValidator.__init_subclass__` / `BaseCipherValidator.__init_subclass__`
        at class definition time) and renders a serializable description suitable
        for printing, logging, or feeding into a CLI `--help` page.

        Returns:
            dict: Keyed by validator name. Each value contains:

                - `validator_type`: `"cert"` or `"cipher"`.
                - `doc`: the validator class docstring (first line).
                - `args`: dict keyed by user arg name, each with `annotation`
                  (string), `default` (the literal default value), and
                  `required` (always `False`, every user arg must declare a
                  default).

        Example:
            ```python
            with CertMonitor("example.com") as monitor:
                for name, info in monitor.describe_validators().items():
                    print(name, info["args"])
            ```
        """
        import inspect

        described: dict[str, dict[str, Any]] = {}
        for name, validator in self.validators.items():
            user_params = getattr(validator, "_user_params", {}) or {}
            args_info: dict[str, dict[str, Any]] = {}
            for param_name, param in user_params.items():
                # `str()` renders both plain classes and parameterized
                # generics; only plain classes need the `<class 'X'>` wrapper
                # unwrapped. Enforcement in __init_subclass__ guarantees every
                # user param has an annotation, so no empty-annotation path.
                rendered = str(param.annotation)
                if rendered.startswith("<class '") and rendered.endswith("'>"):
                    rendered = rendered[len("<class '") : -len("'>")]
                args_info[param_name] = {
                    "annotation": rendered.replace("typing.", ""),
                    "default": param.default,
                    "required": False,
                }

            doc = inspect.getdoc(validator.__class__) or ""
            described[name] = {
                "validator_type": getattr(validator, "validator_type", "cert"),
                "doc": doc.splitlines()[0] if doc else "",
                "args": args_info,
            }
        return described
