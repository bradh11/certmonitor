# protocol_handlers/base.py

import socket
import ssl
from abc import ABC, abstractmethod
from typing import Any


class BaseProtocolHandler(ABC):
    def __init__(self, host: str, port: int, error_handler: Any) -> None:
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self.secure_socket: ssl.SSLSocket | None = None
        self.error_handler = error_handler

    @abstractmethod
    def connect(self) -> dict[str, Any] | None:
        pass

    @abstractmethod
    def fetch_raw_cert(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def close(self) -> None:
        pass
