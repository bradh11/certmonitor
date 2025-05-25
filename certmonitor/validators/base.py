# validators/base.py

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseValidator(ABC):
    """
    Abstract base class for certificate validators.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Returns the name of the validator.

        Returns:
            str: The name of the validator.
        """

    @abstractmethod
    def validate(self, cert: Dict[str, Any], host: str, port: int) -> Dict[str, Any]:
        """
        Validates the given certificate.

        Args:
            cert (dict): The certificate data.
            host (str): The hostname or IP address.
            port (int): The port number.

        Returns:
            dict: The validation result.
        """


class BaseCertValidator(BaseValidator):
    validator_type: str = "cert"

    def validate(
        self, cert_info: Dict[str, Any], host: str, port: int
    ) -> Dict[str, Any]:
        # Default implementation - subclasses should override this
        return None  # type: ignore


class BaseCipherValidator(BaseValidator):
    validator_type: str = "cipher"

    def validate(
        self, cipher_info: Dict[str, Any], host: str, port: int
    ) -> Dict[str, Any]:
        # Default implementation - subclasses should override this
        return None  # type: ignore
