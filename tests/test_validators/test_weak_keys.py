# tests/test_validators/test_weak_keys.py

"""The `weak_keys` validator: public keys whose private half anyone can
recover, checked across the leaf and every certificate in the chain.

The eMudhra fixtures are real: the chains the October 2026 incident's test
hosts served, whose intermediates have P-384 private scalars below 256 (see
`tests/fixtures/emudhra/README.md`). The RSA fixtures are test certificates
built from known primes (see `tests/fixtures/weak_keys/README.md`).
"""

from pathlib import Path

import pytest

from certmonitor import CertMonitor, bundles, certinfo
from certmonitor.config import DEFAULT_VALIDATORS
from certmonitor.validators import VALIDATORS
from certmonitor.validators.weak_keys import WeakKeysValidator

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EMUDHRA_DV_G3B = (
    FIXTURES / "emudhra" / "chains" / "dv-g3b-emudhra.we-have-a-problem.com.pem"
)
EMUDHRA_OV_G3C_AAA = (
    FIXTURES / "emudhra" / "chains" / "ov-g3c-aaa-emudhra.we-have-a-problem.com.pem"
)

# One of the two primes behind tests/fixtures/weak_keys/close-primes.crt.pem.
CLOSE_P = int(
    "9bed86b3172b110768976f277633bd041ec3deed0fd92473a115a0a4962bbddf"
    "9feaebe5ae6858560dcc1e1f04a48522383e0d1fe88deb97000873b067da5926"
    "6626f6fc7b5ad4ca3bb3c76ea4a29922a35f4b54506a9c036785a1bb6194674c"
    "fae0f66102c50aa5f899fad0da0e88ca9490fc9662868085f6e0e2f98bd380bd",
    16,
)


def cert_data(path: Path) -> dict:
    """The shape the collector hands a `cert_data` validator: leaf and chain DER."""
    chain = bundles.certificates_from_bytes(path.read_bytes()).certificates
    return {"der": chain[0], "chain_der": chain}


def google_chain() -> dict:
    chain = [(FIXTURES / f"chain_{i}.der").read_bytes() for i in range(3)]
    return {"der": chain[0], "chain_der": chain}


def validate(cert: dict, **kwargs) -> dict:
    return WeakKeysValidator().validate(cert, "example.com", 443, **kwargs)


def test_is_registered_and_runs_by_default():
    assert isinstance(VALIDATORS["weak_keys"], WeakKeysValidator)
    assert "weak_keys" in DEFAULT_VALIDATORS


def test_a_healthy_chain_passes_with_every_key_checked():
    result = validate(google_chain())
    assert result["is_valid"] is True
    assert result["certs_checked"] == 3
    assert result["findings"] == []
    assert "reason" not in result


def test_the_emudhra_intermediate_fails_while_its_leaf_passes():
    result = validate(cert_data(EMUDHRA_DV_G3B))
    assert result["is_valid"] is False
    assert result["certs_checked"] == 3
    [finding] = result["findings"]
    assert finding["position"] == 1
    assert finding["role"] == "intermediate"
    assert finding["subject"]["commonName"] == "EM DV TLS CA - G3B"
    assert finding["check"] == "ec_small_scalar"
    assert "position 1" in result["reason"]
    assert "EM DV TLS CA - G3B" in result["reason"]


def test_the_recovered_private_key_is_hidden_by_default():
    [finding] = validate(cert_data(EMUDHRA_DV_G3B))["findings"]
    assert "evidence" not in finding


def test_show_evidence_reveals_the_recovered_private_key():
    [finding] = validate(cert_data(EMUDHRA_DV_G3B), show_evidence=True)["findings"]
    assert finding["evidence"] == {"private_scalar": 156}


def test_a_cross_signed_intermediate_with_the_same_key_is_caught():
    result = validate(cert_data(EMUDHRA_OV_G3C_AAA), show_evidence=True)
    [finding] = result["findings"]
    assert finding["position"] == 1
    assert finding["subject"]["commonName"] == "EM OV TLS CA - G3C"
    assert finding["evidence"] == {"private_scalar": 4}


def test_a_bound_below_the_scalar_finds_nothing():
    result = validate(cert_data(EMUDHRA_DV_G3B), ec_scalar_bound=155)
    assert result["is_valid"] is True


def test_rsa_primes_that_are_too_close_are_factored():
    cert = cert_data(FIXTURES / "weak_keys" / "close-primes.crt.pem")
    [finding] = validate(cert, show_evidence=True)["findings"]
    assert finding["position"] == 0
    assert finding["role"] == "leaf"
    assert finding["check"] == "rsa_close_primes"
    p, q = finding["evidence"]["p"], finding["evidence"]["q"]
    assert p == CLOSE_P or q == CLOSE_P


def test_a_roca_key_is_flagged_without_evidence():
    cert = cert_data(FIXTURES / "weak_keys" / "roca.crt.pem")
    [finding] = validate(cert, show_evidence=True)["findings"]
    assert finding["check"] == "rsa_roca"
    assert "evidence" not in finding


def test_every_finding_is_reported_and_the_reason_counts_them():
    close = cert_data(FIXTURES / "weak_keys" / "close-primes.crt.pem")["der"]
    roca = cert_data(FIXTURES / "weak_keys" / "roca.crt.pem")["der"]
    result = validate({"der": close, "chain_der": [close, roca]})
    assert [(f["position"], f["check"]) for f in result["findings"]] == [
        (0, "rsa_close_primes"),
        (1, "rsa_roca"),
    ]
    assert result["reason"].endswith("2 findings in total.")


def test_a_key_off_its_curve_is_not_a_finding():
    # Flipping the last byte of the leaf's EC point keeps the DER the same
    # length but moves the point off P-256, which the search refuses.
    leaf = (FIXTURES / "chain_0.der").read_bytes()
    point = certinfo.certificate_signature_parts(leaf)["key_bits"]
    broken = leaf.replace(point, point[:-1] + bytes([point[-1] ^ 1]))
    result = validate({"der": broken, "chain_der": [broken]})
    assert result["is_valid"] is True
    assert result["certs_checked"] == 1


def test_checks_limits_which_weaknesses_are_looked_for():
    result = validate(
        cert_data(EMUDHRA_DV_G3B), checks=["rsa_close_primes", "rsa_roca"]
    )
    assert result["is_valid"] is True


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"checks": ["ec_small_scalar", "debian_openssl"]}, "unknown check"),
        ({"ec_scalar_bound": -1}, "ec_scalar_bound"),
        ({"ec_scalar_bound": (1 << 24) + 1}, "ec_scalar_bound"),
    ],
)
def test_bad_arguments_raise_value_error(kwargs, message):
    with pytest.raises(ValueError, match=message):
        validate(google_chain(), **kwargs)


def test_only_the_leaf_is_checked_when_the_chain_is_unavailable():
    leaf = cert_data(EMUDHRA_DV_G3B)["der"]
    result = validate({"der": leaf, "chain_der": None, "chain_error": "no chain"})
    assert result["is_valid"] is True
    assert result["certs_checked"] == 1
    assert any("only the leaf" in warning for warning in result["warnings"])


def test_no_certificate_data_is_a_failure_with_a_reason():
    result = validate({})
    assert result["is_valid"] is False
    assert result["reason"]


def test_an_unparseable_chain_member_is_a_warning_not_a_crash():
    cert = cert_data(EMUDHRA_DV_G3B)
    cert["chain_der"] = [cert["chain_der"][0], b"\x30\x00", cert["chain_der"][2]]
    result = validate(cert)
    assert result["is_valid"] is True
    assert result["certs_checked"] == 2
    assert any("position 1" in warning for warning in result["warnings"])


def test_a_default_scan_of_the_emudhra_chain_fails_on_weak_keys():
    with CertMonitor.from_file(str(EMUDHRA_DV_G3B)) as monitor:
        result = monitor.validate()["weak_keys"]
    assert result["is_valid"] is False
    assert result["findings"][0]["subject"]["commonName"] == "EM DV TLS CA - G3B"
