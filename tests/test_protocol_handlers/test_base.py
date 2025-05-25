# tests/test_protocol_handlers/test_base.py

import pytest
from abc import ABC

from certmonitor.protocol_handlers.base import BaseProtocolHandler
from certmonitor.error_handlers import ErrorHandler


class TestBaseProtocolHandler:
    """Test suite for BaseProtocolHandler abstract base class."""

    def test_base_handler_is_abstract(self):
        """Test that BaseProtocolHandler is an abstract base class."""
        assert issubclass(BaseProtocolHandler, ABC)

        # Should not be able to instantiate directly
        with pytest.raises(TypeError):
            BaseProtocolHandler("host", 443, ErrorHandler())

    def test_base_handler_has_abstract_methods(self):
        """Test that BaseProtocolHandler has the required abstract methods."""
        # Check that abstract methods are properly defined
        abstract_methods = BaseProtocolHandler.__abstractmethods__
        expected_methods = {"connect", "fetch_raw_cert", "close"}
        assert abstract_methods == expected_methods

    def test_concrete_implementation_can_inherit(self):
        """Test that a concrete implementation can successfully inherit from BaseProtocolHandler."""

        class ConcreteHandler(BaseProtocolHandler):
            def connect(self):
                return None

            def fetch_raw_cert(self):
                return {"test": "data"}

            def close(self):
                pass

        # Should be able to instantiate concrete implementation
        error_handler = ErrorHandler()
        handler = ConcreteHandler("test.com", 443, error_handler)

        assert handler.host == "test.com"
        assert handler.port == 443
        assert handler.error_handler == error_handler
        assert handler.socket is None
        assert handler.secure_socket is None

    def test_incomplete_concrete_implementation_fails(self):
        """Test that incomplete concrete implementations fail to instantiate."""

        class IncompleteHandler(BaseProtocolHandler):
            def connect(self):
                return None

            # Missing fetch_raw_cert and close methods

        # Should not be able to instantiate due to missing abstract methods
        with pytest.raises(TypeError):
            IncompleteHandler("test.com", 443, ErrorHandler())

    def test_base_handler_initialization(self):
        """Test BaseProtocolHandler initialization through concrete subclass."""

        class TestHandler(BaseProtocolHandler):
            def connect(self):
                return None

            def fetch_raw_cert(self):
                return {}

            def close(self):
                pass

        error_handler = ErrorHandler()
        handler = TestHandler("example.com", 8080, error_handler)

        # Verify initialization
        assert handler.host == "example.com"
        assert handler.port == 8080
        assert handler.socket is None
        assert handler.secure_socket is None
        assert handler.error_handler is error_handler

    def test_base_handler_method_signatures(self):
        """Test that abstract methods have expected signatures."""

        class TestHandler(BaseProtocolHandler):
            def connect(self):
                """Connect method should take no additional arguments."""
                return None

            def fetch_raw_cert(self):
                """Fetch raw cert method should take no additional arguments."""
                return {}

            def close(self):
                """Close method should take no additional arguments."""
                pass

        handler = TestHandler("test.com", 443, ErrorHandler())

        # Should be able to call methods without arguments
        result = handler.connect()
        assert result is None

        cert_data = handler.fetch_raw_cert()
        assert isinstance(cert_data, dict)

        # Close should not return anything
        close_result = handler.close()
        assert close_result is None

    def test_multiple_inheritance_compatibility(self):
        """Test that BaseProtocolHandler works with multiple inheritance."""

        class Mixin:
            def extra_method(self):
                return "mixin_result"

        class MultipleInheritanceHandler(BaseProtocolHandler, Mixin):
            def connect(self):
                return None

            def fetch_raw_cert(self):
                return {"type": "multi_inheritance"}

            def close(self):
                pass

        handler = MultipleInheritanceHandler("test.com", 443, ErrorHandler())

        # Should have methods from both classes
        assert handler.extra_method() == "mixin_result"
        assert handler.fetch_raw_cert() == {"type": "multi_inheritance"}

    def test_handler_attributes_are_mutable(self):
        """Test that handler attributes can be modified after initialization."""

        class TestHandler(BaseProtocolHandler):
            def connect(self):
                return None

            def fetch_raw_cert(self):
                return {}

            def close(self):
                pass

        handler = TestHandler("test.com", 443, ErrorHandler())

        # Should be able to modify attributes
        handler.socket = "mock_socket"
        handler.secure_socket = "mock_secure_socket"

        assert handler.socket == "mock_socket"
        assert handler.secure_socket == "mock_secure_socket"

    def test_polymorphism_with_different_implementations(self):
        """Test polymorphic behavior with different concrete implementations."""

        class SSLTestHandler(BaseProtocolHandler):
            def connect(self):
                return {"protocol": "ssl"}

            def fetch_raw_cert(self):
                return {"cert_type": "ssl_cert"}

            def close(self):
                pass

        class SSHTestHandler(BaseProtocolHandler):
            def connect(self):
                return {"protocol": "ssh"}

            def fetch_raw_cert(self):
                return {"cert_type": "ssh_key"}

            def close(self):
                pass

        # Create handlers
        ssl_handler = SSLTestHandler("ssl.example.com", 443, ErrorHandler())
        ssh_handler = SSHTestHandler("ssh.example.com", 22, ErrorHandler())

        # Test polymorphic behavior
        handlers = [ssl_handler, ssh_handler]

        for handler in handlers:
            assert isinstance(handler, BaseProtocolHandler)
            connect_result = handler.connect()
            cert_result = handler.fetch_raw_cert()

            assert isinstance(connect_result, dict)
            assert isinstance(cert_result, dict)
            assert "protocol" in connect_result
            assert "cert_type" in cert_result

    def test_base_handler_abstract_methods_pass_statements(self):
        """Test base protocol handler abstract methods to ensure pass statements are covered."""

        # Create a handler that deliberately calls the parent abstract methods to hit the pass statements
        class TestHandler(BaseProtocolHandler):
            def __init__(self, host, port):
                super().__init__(host, port, error_handler=None)

            def connect(self):
                # This will execute the pass statement in the base class
                super().connect()
                return None

            def fetch_raw_cert(self):
                # This will execute the pass statement in the base class
                super().fetch_raw_cert()
                return {}

            def close(self):
                # This will execute the pass statement in the base class
                super().close()

        # Test that we can create and use the handler
        handler = TestHandler("example.com", 443)

        # Call the methods that invoke the parent abstract methods
        connect_result = handler.connect()
        cert_result = handler.fetch_raw_cert()
        handler.close()

        # Verify the results
        assert connect_result is None
        assert cert_result == {}
