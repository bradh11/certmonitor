# protocol_handlers/base.py

import socket
import ssl
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseProtocolHandler(ABC):
    def __init__(self, host: str, port: int, error_handler: Any) -> None:
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.secure_socket: Optional[ssl.SSLSocket] = None
        self.error_handler = error_handler

    @abstractmethod
    def connect(self) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def fetch_raw_cert(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def close(self) -> None:
        pass
