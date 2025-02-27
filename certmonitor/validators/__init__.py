from .expiration import ExpirationValidator
from .hostname import HostnameValidator
from .key_info import KeyInfoValidator
from .root_certificate_validator import RootCertificateValidator
from .subject_alt_names import SubjectAltNamesValidator

# ... import other validators


def get_validators():
    return [
        ExpirationValidator(),
        HostnameValidator(),
        KeyInfoValidator(),
        SubjectAltNamesValidator(),
        RootCertificateValidator(),
        # ... other validators
    ]
