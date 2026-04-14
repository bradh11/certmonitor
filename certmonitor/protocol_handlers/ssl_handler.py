# protocol_handlers/ssl_handler.py

import logging
import socket
import ssl
import warnings
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from .base import BaseProtocolHandler


class SSLHandler(BaseProtocolHandler):
    def __init__(self, host: str, port: int, error_handler: Any) -> None:
        super().__init__(host, port, error_handler)
        self.socket: Optional[socket.socket] = None
        self.secure_socket: Optional[ssl.SSLSocket] = None
        self.tls_version: Optional[str] = None

    def get_supported_protocols(self) -> List[int]:
        supported_protocols: List[int] = []
        # NOTE: Legacy TLS/SSL versions are intentionally included for security assessment
        # This tool needs to detect and analyze weak configurations in legacy systems
        for protocol in [
            ssl.PROTOCOL_TLS_CLIENT,
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_1,  # Intentionally weak - for legacy detection
            ssl.PROTOCOL_TLSv1,  # Intentionally weak - for legacy detection
            ssl.PROTOCOL_SSLv23,  # Intentionally weak - for legacy detection
        ]:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=DeprecationWarning)
                    ssl.SSLContext(protocol)
                supported_protocols.append(protocol)
            except AttributeError:
                pass
        return supported_protocols

    def connect(self) -> Optional[Dict[str, Any]]:
        protocols = self.get_supported_protocols()
        for protocol in protocols:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=DeprecationWarning)
                    context = ssl.SSLContext(protocol)
                    context.set_ciphers("ALL:@SECLEVEL=0")
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.options &= ~ssl.OP_NO_RENEGOTIATION

                self.socket = socket.create_connection(
                    (self.host, self.port), timeout=10
                )
                self.secure_socket = context.wrap_socket(
                    self.socket, server_hostname=self.host
                )
                self.tls_version = self.secure_socket.version()
                return None  # Explicitly return None on success
            except ssl.SSLError as ssl_e:
                if "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in str(ssl_e):
                    # Retry with unsafe legacy renegotiation enabled
                    try:
                        context.options &= ~ssl.OP_NO_RENEGOTIATION
                        self.socket = socket.create_connection(
                            (self.host, self.port), timeout=10
                        )
                        self.secure_socket = context.wrap_socket(
                            self.socket, server_hostname=self.host
                        )
                        self.tls_version = self.secure_socket.version()
                        return None
                    except Exception as retry_e:
                        logging.error(
                            f"Error connecting with unsafe legacy renegotiation: {retry_e}"
                        )
                        # Continue to next protocol instead of returning error
                        if self.socket:
                            self.socket.close()
                            self.socket = None
                        continue
                # Continue to next protocol for other SSL errors
                if self.socket:
                    self.socket.close()
                    self.socket = None
                continue
            except Exception:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                # Continue to next protocol

        # If all protocols fail
        return cast(
            Dict[str, Any],
            self.error_handler.handle_error(
                "SSLError",
                "Failed to establish SSL connection with any protocol",
                self.host,
                self.port,
            ),
        )

    def fetch_raw_cert(self) -> Dict[str, Any]:
        if not self.secure_socket:
            return cast(
                Dict[str, Any],
                self.error_handler.handle_error(
                    "ConnectionError",
                    "SSL connection not established",
                    self.host,
                    self.port,
                ),
            )
        try:
            cert = self.secure_socket.getpeercert(binary_form=True)
            if cert is None:
                return cast(
                    Dict[str, Any],
                    self.error_handler.handle_error(
                        "CertificateError",
                        "No certificate available",
                        self.host,
                        self.port,
                    ),
                )
            chain_der, chain_error = self._fetch_chain_der()
            return {
                "cert_info": self.secure_socket.getpeercert(),
                "der": cert,
                "pem": ssl.DER_cert_to_PEM_cert(cert),
                "chain_der": chain_der,
                "chain_error": chain_error,
            }
        except Exception as e:
            return cast(
                Dict[str, Any],
                self.error_handler.handle_error(
                    "CertificateError", str(e), self.host, self.port
                ),
            )

    def _fetch_chain_der(self) -> Tuple[Optional[List[bytes]], Optional[str]]:
        """Retrieve the peer certificate chain as a list of DER byte strings.

        Python 3.13 exposes ``SSLSocket.get_verified_chain()``, which returns
        DER bytes directly. Python 3.10–3.12 only exposes the chain through
        the private ``_sslobj`` attribute as ``_ssl.Certificate`` instances,
        so we pull those, ask each for its PEM, and convert back to DER using
        the public ``ssl.PEM_cert_to_DER_cert`` helper. On 3.8/3.9 there is
        no stdlib-only way to obtain the chain and we return an informative
        error instead.
        """
        if not self.secure_socket:
            return None, "SSL connection not established"
        if hasattr(self.secure_socket, "get_verified_chain"):
            try:
                chain = self.secure_socket.get_verified_chain()
                return list(chain), None
            except Exception as exc:  # noqa: BLE001
                return None, f"Failed to retrieve certificate chain: {exc}"

        sslobj = getattr(self.secure_socket, "_sslobj", None)
        if sslobj is not None and hasattr(sslobj, "get_unverified_chain"):
            try:
                chain_certs = sslobj.get_unverified_chain()
                ders = [ssl.PEM_cert_to_DER_cert(c.public_bytes()) for c in chain_certs]
                return ders, None
            except Exception as exc:  # noqa: BLE001
                return None, f"Failed to retrieve certificate chain: {exc}"

        return None, (
            "Certificate chain retrieval requires Python 3.10 or newer; "
            "on this interpreter only the leaf certificate is available."
        )

    def fetch_raw_cipher(self) -> Union[Tuple[str, str, Optional[int]], Dict[str, Any]]:
        if not self.secure_socket:
            return cast(
                Dict[str, Any],
                self.error_handler.handle_error(
                    "ConnectionError",
                    "SSL connection not established",
                    self.host,
                    self.port,
                ),
            )
        cipher_info = self.secure_socket.cipher()
        if cipher_info is None:
            return cast(
                Dict[str, Any],
                self.error_handler.handle_error(
                    "CipherError",
                    "No cipher information available",
                    self.host,
                    self.port,
                ),
            )
        # cipher_info should be a 3-tuple when not None, but we check to be safe
        if isinstance(cipher_info, tuple) and len(cipher_info) == 3:
            return cipher_info
        # This should not happen in practice, but we handle it defensively
        return cast(  # type: ignore[unreachable]
            Dict[str, Any],
            self.error_handler.handle_error(
                "CipherError", "Cipher information is not a tuple", self.host, self.port
            ),
        )

    def check_connection(self) -> bool:
        if self.secure_socket:
            try:
                self.secure_socket.getpeername()
                return True
            except Exception as e:
                logging.error(f"Error checking connection: {e}")
                return False
        return False

    def close(self) -> None:
        if self.secure_socket:
            self.secure_socket.close()
        if self.socket:
            self.socket.close()
        self.secure_socket = None
        self.socket = None
        self.tls_version = None

    def get_protocol_version(self) -> str:
        return self.tls_version or "Unknown"
