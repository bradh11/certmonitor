# protocol_handlers/ssh_handler.py

import re
import socket
from typing import Any, Dict, Optional, cast

from .base import BaseProtocolHandler


class SSHHandler(BaseProtocolHandler):
    def connect(self) -> Optional[Dict[str, Any]]:
        try:
            self.socket = socket.create_connection((self.host, self.port), timeout=10)
            return None
        except socket.error as e:
            return cast(
                Optional[Dict[str, Any]],
                self.error_handler.handle_error(
                    "SocketError", str(e), self.host, self.port
                ),
            )
        except Exception as e:
            return cast(
                Optional[Dict[str, Any]],
                self.error_handler.handle_error(
                    "UnknownError", str(e), self.host, self.port
                ),
            )

    def fetch_raw_cert(self) -> Dict[str, Any]:
        try:
            if not self.socket:
                return cast(
                    Dict[str, Any],
                    self.error_handler.handle_error(
                        "ConnectionError", "Socket not connected", self.host, self.port
                    ),
                )

            ssh_banner = self.socket.recv(1024).decode("ascii", errors="ignore").strip()
            match = re.match(r"^SSH-(\d+\.\d+)-(.*)$", ssh_banner)
            if match:
                return {
                    "protocol": "ssh",
                    "ssh_version_string": ssh_banner,
                    "protocol_version": match.group(1),
                    "software_version": match.group(2),
                }
            else:
                return cast(
                    Dict[str, Any],
                    self.error_handler.handle_error(
                        "SSHError", "Invalid SSH banner", self.host, self.port
                    ),
                )
        except Exception as e:
            return cast(
                Dict[str, Any],
                self.error_handler.handle_error(
                    "SSHError", str(e), self.host, self.port
                ),
            )

    def close(self) -> None:
        if self.socket:
            self.socket.close()
            self.socket = None

    def check_connection(self) -> bool:
        if not self.socket:
            return False
        try:
            self.socket.getpeername()
            return True
        except socket.error:
            return False
