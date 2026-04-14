# validators/base.py

"""Base classes for certmonitor validators.

Contributors writing a new validator should subclass :class:`BaseCertValidator`
(for validators that inspect certificate data) or :class:`BaseCipherValidator`
(for validators that inspect cipher suite data) and implement ``validate``.

The first three positional parameters of ``validate`` are supplied by the
dispatcher — the parsed cert or cipher data, the host, and the port. Any
additional user-configurable arguments must be declared as **keyword-only**
parameters, each with a **type annotation** and a **default value**. The
class-level ``__init_subclass__`` hook enforces this at import time, caches the
discovered user parameters, and exposes them for dispatch and introspection.
"""

import inspect
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict, FrozenSet, Mapping


class BaseValidator(ABC):
    """Abstract base class for certificate and cipher validators."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name used to register and look up this validator."""

    @abstractmethod
    def validate(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Run the validator and return a result dict."""


class _ValidatorBase(BaseValidator):
    """Internal base that handles user-arg discovery for concrete validators.

    Subclasses set ``_framework_arity`` to the number of positional parameters
    the dispatcher supplies to ``validate`` (typically 3: the parsed data, the
    host, and the port). Everything keyword-only after those positional
    parameters is treated as a user-configurable argument and must be
    annotated and have a default value.
    """

    _framework_arity: ClassVar[int] = 0
    _user_params: ClassVar[Mapping[str, inspect.Parameter]] = {}
    _user_param_names: ClassVar[FrozenSet[str]] = frozenset()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        # Only inspect ``validate`` if this class actually defines one. The
        # intermediate ``BaseCertValidator`` / ``BaseCipherValidator`` bases
        # define stubs and run through here; concrete subclasses also do.
        if "validate" not in cls.__dict__:
            return

        sig = inspect.signature(cls.validate)

        # Framework params are the first ``_framework_arity`` non-``self``
        # positional parameters, regardless of what they are named.
        user_params: Dict[str, inspect.Parameter] = {}
        problems = []
        positional_seen = 0
        arity = cls._framework_arity

        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
            if param.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                positional_seen += 1
                if positional_seen <= arity:
                    # Framework-supplied positional parameter. Skip.
                    continue
                # A positional-or-keyword param beyond the framework arity is
                # a user arg declared the wrong way.
                problems.append(
                    f"{param_name!r}: must be keyword-only (declare after `*`)"
                )
                continue
            if param.kind is inspect.Parameter.VAR_POSITIONAL:
                problems.append(
                    f"{param_name!r}: *args is not allowed for user args; "
                    "declare keyword-only parameters instead"
                )
                continue
            if param.kind is inspect.Parameter.VAR_KEYWORD:
                problems.append(
                    f"{param_name!r}: **kwargs is not allowed for user args; "
                    "declare each argument explicitly"
                )
                continue
            # Keyword-only parameter — a user arg.
            if param.annotation is inspect.Parameter.empty:
                problems.append(f"{param_name!r}: missing type annotation")
            if param.default is inspect.Parameter.empty:
                problems.append(f"{param_name!r}: missing default value")
            user_params[param_name] = param

        if problems:
            raise TypeError(
                f"Validator {cls.__name__}.validate() has malformed user args:\n  - "
                + "\n  - ".join(problems)
                + "\n\nUser args must be keyword-only, annotated, and defaulted. "
                "Example:\n"
                "    def validate(self, cert, host, port, *, "
                "alternate_names: Optional[List[str]] = None) -> Dict[str, Any]: ..."
            )

        cls._user_params = user_params
        cls._user_param_names = frozenset(user_params)


class BaseCertValidator(_ValidatorBase):
    """Base class for validators that inspect parsed certificate data."""

    validator_type: str = "cert"
    _framework_arity: ClassVar[int] = 3

    def validate(
        self, cert_info: Dict[str, Any], host: str, port: int
    ) -> Dict[str, Any]:
        # Default implementation — subclasses override.
        return None  # type: ignore[return-value]


class BaseCipherValidator(_ValidatorBase):
    """Base class for validators that inspect negotiated cipher suite data."""

    validator_type: str = "cipher"
    _framework_arity: ClassVar[int] = 3

    def validate(
        self, cipher_info: Dict[str, Any], host: str, port: int
    ) -> Dict[str, Any]:
        # Default implementation — subclasses override.
        return None  # type: ignore[return-value]
