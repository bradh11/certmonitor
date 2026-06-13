# protocol_handlers/__init__.py

"""Protocol handlers for CertMonitor.

Each handler knows how to talk to one kind of endpoint (SSL/TLS or SSH):
establish the connection, fetch the certificate, and, for TLS, retrieve
cipher information. ``CertMonitor`` selects the right handler after
protocol detection; you rarely use these directly.
"""

from .base import BaseProtocolHandler
from .ssh_handler import SSHHandler
from .ssl_handler import SSLHandler

__all__ = ["BaseProtocolHandler", "SSHHandler", "SSLHandler"]
