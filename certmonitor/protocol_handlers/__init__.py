# protocol_handlers/__init__.py

"""Everything about talking to a port lives here.

The handlers know how to fetch a certificate from one kind of endpoint
(SSL/TLS or SSH). Around them sit the pieces every connection shares:
`connection` opens plaintext and TLS streams, `proxy` tunnels them through
HTTP CONNECT or SOCKS5, `starttls` runs and discovers STARTTLS preambles,
and `detection` decides which handler a port needs.
`CertMonitor` drives all of this; you rarely use it directly.
"""

from .base import BaseProtocolHandler
from .connection import open_stream, open_tls_stream
from .detection import Detected, ProtocolDetectionError, detect
from .proxy import ProxyConfig, ProxyError, parse_proxy
from .ssh_handler import SSHHandler
from .ssl_handler import SSLHandler

__all__ = [
    "BaseProtocolHandler",
    "Detected",
    "ProtocolDetectionError",
    "ProxyConfig",
    "ProxyError",
    "SSHHandler",
    "SSLHandler",
    "detect",
    "open_stream",
    "open_tls_stream",
    "parse_proxy",
]
