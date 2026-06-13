# tests/test_validators/test_result_envelope.py

"""Conformance tests for the standard validator result envelope.

Every PQ validator result must satisfy the contract declared in
``certmonitor.validators.results.ValidationResult``:

- ``is_valid`` is always present and a strict ``bool`` (never ``None``),
- ``reason`` is present iff ``is_valid`` is ``False``, and is a
  non-empty human-readable string,
- ``warnings``, when present, is a list of strings,
- the reserved envelope keys are never reused for data.

Legacy validators (e.g. ``key_info``'s ``is_valid: None``) are not yet
migrated and are intentionally not covered here.
"""

import sys

import pytest

from certmonitor.validators import ValidationResult
from certmonitor.validators.pq_chain import PqChainValidator
from certmonitor.validators.pq_key_exchange import PqKeyExchangeValidator
from certmonitor.validators.pq_signature import PqSignatureValidator

ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"
TLS13 = {"protocol_version": "TLSv1.3"}


def assert_envelope(result):
    """Assert that a validator result conforms to the standard envelope."""
    assert isinstance(result, dict)

    assert "is_valid" in result, "is_valid must always be present"
    assert isinstance(result["is_valid"], bool), "is_valid must be a strict bool"

    if result["is_valid"]:
        assert "reason" not in result, "reason must be absent when valid"
    else:
        assert "reason" in result, "reason must be present when invalid"
        assert isinstance(result["reason"], str) and result["reason"].strip()

    if "warnings" in result:
        assert isinstance(result["warnings"], list)
        assert all(isinstance(w, str) for w in result["warnings"])


def chain_cert(key_alg, sig_oid, self_signed=False):
    return {
        "subject": {"commonName": "x"},
        "public_key_info": {"algorithm": key_alg, "size": 2048},
        "signature_algorithm_oid": sig_oid,
        "is_self_signed": self_signed,
    }


def leaf_data(key_alg, sig_oid):
    return {"chain_analysis": {"certs": [chain_cert(key_alg, sig_oid)]}}


PQ_SIGNATURE_CASES = [
    leaf_data("ml-dsa-65", ML_DSA_65_OID),  # valid: pure PQ
    leaf_data("rsaEncryption", SHA256_RSA_OID),  # invalid: classical
    {},  # invalid: no analysis available at all
    {"chain_analysis": {"error": "parse failed"}},  # invalid: analysis errored
]

PQ_CHAIN_CASES = [
    leaf_data("ml-dsa-65", ML_DSA_65_OID),  # valid: PQ leaf
    leaf_data("rsaEncryption", SHA256_RSA_OID),  # invalid: classical leaf
    {"chain_error": "not supported on this interpreter"},  # invalid: chain error
    {},  # invalid: chain never fetched
    {"chain_analysis": {"certs": []}},  # invalid: empty chain
]

PQ_KEY_EXCHANGE_PROBES = [
    {
        "result": "group",
        "id": 4588,
        "name": "X25519MLKEM768",
        "kind": "hybrid_pq",
        "is_pq": True,
    },
    {
        "result": "group",
        "id": 29,
        "name": "x25519",
        "kind": "classical_ecdh",
        "is_pq": False,
    },
    {"result": "n/a", "protocol": "TLSv1.2", "reason": "TLSv1.2 has no PQ KEMs"},
    {"result": "error", "error": "ConnectError", "message": "could not connect"},
    {"result": "something-unexpected"},
]


class TestEnvelopeConformance:
    @pytest.mark.parametrize("cert_data", PQ_SIGNATURE_CASES)
    def test_pq_signature(self, cert_data):
        assert_envelope(PqSignatureValidator().validate(cert_data, "h", 443))

    @pytest.mark.parametrize("cert_data", PQ_CHAIN_CASES)
    def test_pq_chain(self, cert_data):
        assert_envelope(PqChainValidator().validate(cert_data, "h", 443))

    @pytest.mark.parametrize("probe", PQ_KEY_EXCHANGE_PROBES)
    def test_pq_key_exchange(self, probe):
        assert_envelope(PqKeyExchangeValidator().validate(TLS13, probe, "h", 443))

    def test_strict_mode_results_also_conform(self):
        assert_envelope(
            PqSignatureValidator().validate(
                leaf_data("ml-dsa-65", SHA256_RSA_OID),
                "h",
                443,
                require_pq_signature=True,
            )
        )
        assert_envelope(
            PqChainValidator().validate(
                leaf_data("ml-dsa-65", SHA256_RSA_OID),
                "h",
                443,
                require_full_chain=True,
            )
        )


class TestValidationResultSchema:
    def test_importable_from_validators_package(self):
        from certmonitor.validators.results import (
            ValidationResult as FromModule,
        )

        assert ValidationResult is FromModule

    def test_results_are_plain_dicts_at_runtime(self):
        # The schema is static-only: results must stay JSON-serializable
        # plain dicts, not dataclass or TypedDict instances of some
        # other runtime type.
        import json

        r = PqSignatureValidator().validate(
            leaf_data("ml-dsa-65", ML_DSA_65_OID), "h", 443
        )
        assert type(r) is dict
        json.dumps(r)

    @pytest.mark.skipif(
        sys.version_info < (3, 9),
        reason="TypedDict.__required_keys__ requires Python 3.9+",
    )
    def test_reserved_keys_match_contract(self):
        # The five reserved envelope keys, exactly.
        required = set(ValidationResult.__required_keys__)
        optional = set(ValidationResult.__optional_keys__)
        assert required == {"is_valid"}
        assert optional == {"reason", "warnings", "error", "message"}
