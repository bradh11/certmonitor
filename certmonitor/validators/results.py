# validators/results.py

"""The standard validator result envelope.

Every validator returns a plain dict (JSON-serializable, accessed with
``result["is_valid"]``). These :class:`~typing.TypedDict` classes declare
the *schema* of that dict without changing its runtime type, so mypy can
enforce the contract while consumers keep working with ordinary dicts.

The envelope contract:

==============  =================  ====================================
Key             Type               Rule
==============  =================  ====================================
``is_valid``    ``bool``           Always present, strict bool — never
                                   ``None`` in conforming validators.
``reason``      ``str``            Present **iff** ``is_valid`` is
                                   ``False``. One human-readable sentence
                                   stating the primary cause.
``warnings``    ``List[str]``      Optional. Non-fatal findings.
``error``       ``str``            Optional. Machine-readable error class
                                   on operational failures (connection
                                   refused, probe failed, …).
``message``     ``str``            Optional. Human-readable detail
                                   accompanying ``error``.
==============  =================  ====================================

All other keys are validator-specific **data** fields: snake_case,
documented on the validator's docs page, and stable across releases. The
five reserved keys above are never reused for data.

Operational failures are still results: a validator whose data source
cannot be fetched reports ``is_valid: False`` with a ``reason`` (plus
``error``/``message`` where a machine-readable class helps) — it is never
silently omitted from ``validate()`` output.

A validator declares its full shape by extending :class:`ValidationResult`
with its data fields (see ``pq_signature.py`` for an example)::

    class MyResult(ValidationResult, total=False):
        my_data_field: str

Note:
    ``typing.NotRequired`` is only available on Python 3.11+, and the
    project has a zero-dependency rule (no ``typing_extensions``), so on the
    3.10 floor we use the two-class required/optional split below.
"""

from typing import TypedDict


class _ValidationResultBase(TypedDict):
    """The required envelope keys — every validator result carries these."""

    is_valid: bool


class ValidationResult(_ValidationResultBase, total=False):
    """Standard validator result envelope (see module docstring).

    ``is_valid`` is required; the four optional keys below are reserved
    and may only carry envelope semantics. Validator-specific data fields
    are declared by extending this class with ``total=False``.
    """

    reason: str
    warnings: list[str]
    error: str
    message: str
