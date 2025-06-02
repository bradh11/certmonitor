# validators/__init__.py
from typing import Any

from .expiration import ExpirationValidator
from .hostname import HostnameValidator
from .key_info import KeyInfoValidator
from .root_certificate_validator import RootCertificateValidator
from .sensitive_date import SensitiveDateValidator
from .subject_alt_names import SubjectAltNamesValidator
from .tls_version import TLSVersionValidator
from .weak_cipher import WeakCipherValidator

# ... Import other validators as needed


# A global registry of validator instances
VALIDATORS = {
    "expiration": ExpirationValidator(),
    "hostname": HostnameValidator(),
    "key_info": KeyInfoValidator(),
    "subject_alt_names": SubjectAltNamesValidator(),
    "root_certificate": RootCertificateValidator(),
    "sensitive_date": SensitiveDateValidator(),
    "tls_version": TLSVersionValidator(),
    "weak_cipher": WeakCipherValidator(),
    # ... add any other default validators here
}


def register_validator(validator_instance: Any) -> None:
    """
    Register a custom validator instance with the system.

    Args:
        validator_instance (BaseValidator): An instance of a validator class
                                            that inherits from BaseValidator.
    """
    name = validator_instance.name
    VALIDATORS[name] = validator_instance


def list_validators() -> list:
    """
    Lists all currently registered validators.

    Returns:
        list: A list of validator names.
    """
    return list(VALIDATORS.keys())


def get_enabled_validators() -> list:
    """
    Placeholder function for getting enabled validators.

    Returns:
        list: A list of enabled validator names.
    """
    # Implementation goes here
    return []
