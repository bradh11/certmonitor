# protocol_handlers/ssl_handler.py

import logging
import socket
import ssl
from typing import Any, cast

from .base import BaseProtocolHandler
from .connection import open_tls_stream


class SSLHandler(BaseProtocolHandler):
    def __init__(self, host: str, port: int, error_handler: Any) -> None:
        super().__init__(host, port, error_handler)
        self.socket: socket.socket | None = None
        self.secure_socket: ssl.SSLSocket | None = None
        self.server_hostname = host
        self.timeout = 10.0
        self.client_cert: str | None = None
        self.client_key: str | None = None
        self.starttls: str | None = None
        self.tls_version: str | None = None

    def _build_context(
        self,
        *,
        maximum_version: ssl.TLSVersion | None = None,
        legacy_server_connect: bool = False,
    ) -> ssl.SSLContext:
        """Build the permissive collection context.

        One `PROTOCOL_TLS_CLIENT` context with the version range opened all the
        way down lets OpenSSL negotiate anything the server supports, including
        TLS 1.0 and 1.1 where the local build allows them, without touching the
        deprecated per-protocol constants. Verification is off on purpose: this
        connection collects evidence, and trust is checked separately.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = maximum_version or ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.options &= ~ssl.OP_NO_RENEGOTIATION
        if legacy_server_connect:
            context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        if self.client_cert:
            context.load_cert_chain(self.client_cert, self.client_key)
        return context

    def _attempt(self, **options: Any) -> str | None:
        """Open one collection connection; return the error text on failure."""
        try:
            self.secure_socket = open_tls_stream(
                self.host,
                self.port,
                self.timeout,
                self._build_context(**options),
                server_hostname=self.server_hostname,
                starttls=self.starttls,
                proxy=self.proxy,
            )
            self.tls_version = self.secure_socket.version()
            return None
        except Exception as exc:  # noqa: BLE001
            logging.debug("TLS collection attempt failed for %s: %s", self.host, exc)
            return str(exc)

    def connect(self) -> dict[str, Any] | None:
        """Negotiate a permissive TLS session for certificate collection.

        The first attempt offers every protocol version the local build
        supports. If that fails, a second attempt caps the offer at TLS 1.2 for
        servers that mishandle a TLS 1.3 ClientHello. A server that demands
        legacy renegotiation gets one retry with that option enabled. Every
        attempt gets its own `timeout`.
        """
        attempts: list[dict[str, Any]] = [
            {},
            {"maximum_version": ssl.TLSVersion.TLSv1_2},
        ]
        for options in attempts:
            error = self._attempt(**options)
            if error is None:
                return None
            if "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in error.upper().replace(
                " ", "_"
            ):
                if self._attempt(**options, legacy_server_connect=True) is None:
                    return None
        return cast(
            dict[str, Any],
            self.error_handler.handle_error(
                "SSLError",
                "Failed to establish SSL connection with any protocol",
                self.host,
                self.port,
            ),
        )

    def fetch_raw_cert(self) -> dict[str, Any]:
        if not self.secure_socket:
            return cast(
                dict[str, Any],
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
                    dict[str, Any],
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
                dict[str, Any],
                self.error_handler.handle_error(
                    "CertificateError", str(e), self.host, self.port
                ),
            )

    def _fetch_chain_der(self) -> tuple[list[bytes] | None, str | None]:
        """Retrieve the peer certificate chain as a list of DER byte strings.

        Python 3.13 exposes `SSLSocket.get_verified_chain()`, which returns
        DER bytes directly. Python 3.10 to 3.12 only exposes the chain through
        the private `_sslobj` attribute as `_ssl.Certificate` instances,
        so we pull those, ask each for its PEM, and convert back to DER using
        the public `ssl.PEM_cert_to_DER_cert` helper. If neither API is
        available, an informative error is returned.
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
            "Certificate chain retrieval is not available on this interpreter; "
            "only the leaf certificate could be obtained."
        )

    def fetch_raw_cipher(self) -> tuple[str, str, int | None] | dict[str, Any]:
        if not self.secure_socket:
            return cast(
                dict[str, Any],
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
                dict[str, Any],
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
            dict[str, Any],
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
