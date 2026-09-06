import pytest

from certmonitor.validators.subject_alt_names import SubjectAltNamesValidator


def validate(sans, alternates, host="primary.test"):
    return SubjectAltNamesValidator().validate(
        {"cert_info": {"subjectAltName": sans}},
        host,
        443,
        alternate_names=alternates,
    )


def test_alternates_decide_validity_when_requested():
    result = validate({"DNS": "alternate.test"}, ["alternate.test"])
    assert result["is_valid"] is True
    assert result["contains_host"]["is_valid"] is False  # reported, not decisive
    assert result["count"] == 1


def test_every_alternate_must_match():
    result = validate({"DNS": "alternate.test"}, ["alternate.test", "missing.test"])
    assert result["is_valid"] is False
    assert result["contains_alternate"]["alternate.test"]["is_valid"] is True
    assert result["contains_alternate"]["missing.test"]["is_valid"] is False


@pytest.mark.parametrize("names", [None, []])
def test_no_alternates_falls_back_to_the_primary_host(names):
    result = validate({"DNS": "primary.test"}, names)
    assert result["is_valid"] is True
    assert result["contains_host"]["name"] == "primary.test"
    assert "status" not in result
    missing = validate({"DNS": "other.test"}, names)
    assert missing["is_valid"] is False
    assert "primary.test is not included in the SANs" in missing["reason"]


@pytest.mark.parametrize(
    "sans,name,valid",
    [
        ({"DNS": "notexample.com"}, "example.com", False),
        ({"DNS": "*.example.com"}, "API.EXAMPLE.COM", True),
        ({"DNS": "*.example.com"}, "a.b.example.com", False),
        ({"DNS": "*.example.com"}, "example.com", False),
        ({"IP Address": "192.0.2.1"}, "192.0.2.1", True),
        ({"DNS": "192.0.2.1"}, "192.0.2.1", False),
        ({"IP Address": ["invalid", "2001:0db8::1"]}, "2001:db8::1", True),
        ([("DNS", "example.com")], "example.com", True),
        ({}, "example.com", False),
    ],
)
def test_alternate_identity_matching(sans, name, valid):
    result = validate(sans, [name])
    assert result["is_valid"] is valid


@pytest.mark.parametrize("names", ["example.com", [None], [""]])
def test_invalid_alternate_arguments(names):
    with pytest.raises(ValueError):
        validate({}, names)


@pytest.mark.parametrize("alternates", [None, ["san0.test"]])
def test_high_san_count_warns_with_or_without_alternates(alternates):
    sans = {"DNS": [f"san{i}.test" for i in range(150)]}
    result = validate(sans, alternates)
    assert any("unusually high number of SANs (150)" in w for w in result["warnings"])


def test_tuple_of_alternates_is_accepted():
    result = validate({"DNS": ["a.test", "b.test"]}, ("a.test", "b.test"))
    assert result["is_valid"] is True
