"""Revocation evidence for the `revocation` validator: OCSP and CRL.

The validator decides; this module gathers. `RevocationEvidence` answers
two questions lazily, `ocsp()` and `crl()`, each returning one plain dict
that says what the source reported and whether that answer is proven.

OCSP requests are built here, hashed with `hashlib`, sent with the small
HTTP client in `protocol_handlers.http`, and parsed by the in-house Rust
DER parser, which also verifies the responder's signature (RSA PKCS#1 v1.5
and ECDSA over P-256 and P-384). A response signed by the issuing CA, or by
a delegated responder certificate the CA issued for OCSP signing, carries
`signature_verified: True`; anything else says why in `verification_error`.
CRLs are fetched here and verified the same way: the CRL must name the
leaf's issuer and carry that issuer's signature. The CRL's signature outcome
is recorded before its list is consulted, and the validator discards any
answer whose signature failed. No second connection is opened for either
method, so an answer can only describe the certificate that was collected.

Fetched CRLs and OCSP answers are cached process-wide: verified answers are
cached until their `nextUpdate`, never longer than a day; an answer with no
`nextUpdate` is cached for at most an hour and, for OCSP, never past
`thisUpdate` plus `max_age`; failed or unverifiable answers are fetched
again next time. A monitor built from a file never touches the network, so
both methods report `unsupported` for it.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from certmonitor import bundles, certinfo
from certmonitor.protocol_handlers import http
from certmonitor.protocol_handlers.proxy import ProxyConfig
from certmonitor.signatures import FAILED, UNSUPPORTED, VERIFIED
from certmonitor.signatures import verify as verify_signature_bytes

METHODS = ("ocsp", "crl")
OCSP_CONTENT_TYPE = "application/ocsp-request"
OCSP_RESPONSE_TYPE = "application/ocsp-response"
CA_ISSUERS_ACCEPT = "application/pkix-cert, application/pkcs7-mime"

_OID_SHA1 = b"\x06\x05\x2b\x0e\x03\x02\x1a"
_SHA1_OID_TEXT = "1.3.14.3.2.26"
_OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
_CACHE_CEILING_SECONDS = 24 * 60 * 60
_DEFAULT_TTL_SECONDS = 60 * 60
_CACHE_LIMIT = 256
_OCSP_MAX_AGE_SECONDS = 24 * 60 * 60
_MAX_LIFETIME_SECONDS = 10 * 24 * 60 * 60


# --- small helpers -----------------------------------------------------------------


def _der(tag: int, content: bytes) -> bytes:
    """Encode one DER TLV."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    size = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content


def format_time(unix: int | None) -> str | None:
    """Render unix seconds as an ISO 8601 UTC timestamp, or pass `None` through."""
    if unix is None:
        return None
    return datetime.fromtimestamp(unix, timezone.utc).isoformat()


def pem_to_der(text: bytes) -> bytes:
    """Decode the first PEM block in `text` (certificate or CRL) to DER."""
    lines = text.decode("ascii", errors="replace").splitlines()
    body = [
        line.strip() for line in lines if line.strip() and not line.startswith("-----")
    ]
    return base64.b64decode("".join(body), validate=True)


def http_urls(values: Any) -> list[str]:
    """The `http(s)` URLs in a certificate field; LDAP and file pointers are skipped."""
    if not values:
        return []
    return [
        value
        for value in values
        if str(value).lower().startswith(("http://", "https://"))
    ]


# --- caches --------------------------------------------------------------------------


class _Cache:
    """A bounded, thread-safe map of key to (expires_at, value)."""

    def __init__(self, limit: int = _CACHE_LIMIT) -> None:
        self._entries: dict[Any, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._limit = limit

    def get(self, key: Any, now: float) -> Any | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                del self._entries[key]
                return None
            return value

    def put(self, key: Any, value: Any, expires_at: float) -> None:
        with self._lock:
            if len(self._entries) >= self._limit:
                oldest = min(self._entries, key=self._expiry)
                del self._entries[oldest]
            self._entries[key] = (expires_at, value)

    def _expiry(self, key: Any) -> float:
        return self._entries[key][0]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


CRL_CACHE = _Cache()
OCSP_CACHE = _Cache()


def _expiry_for(
    this_update: int, next_update: int | None, now: float, max_age: float
) -> float:
    """When a fetched answer stops being reusable.

    Never later than the answer's own `nextUpdate`: a cache must not extend
    the validity of signed evidence. Capped at a day for answers that promise
    more. An answer without `nextUpdate` is reusable until `thisUpdate` plus
    `max_age`, and never longer than an hour, so re-fetching a historical
    response cannot give it a fresh lease. Whatever `nextUpdate` says, nothing
    is reused once `thisUpdate` is ten days old, the same ceiling a fresh
    response is held to.
    """
    ceiling = float(this_update + _MAX_LIFETIME_SECONDS)
    if next_update is None:
        return min(this_update + max_age, now + _DEFAULT_TTL_SECONDS, ceiling)
    return min(float(next_update), now + _CACHE_CEILING_SECONDS, ceiling)


def _still_current(next_update: int | None, now: float) -> bool:
    return next_update is None or next_update > now


def _ocsp_freshness_problem(
    this_update: int, next_update: int | None, now: float, max_age: float
) -> tuple[str, str] | None:
    """Why an OCSP response's dates make it unusable at `now`, or `None`.

    One rule for fetched and cached responses alike: `thisUpdate` may not be
    in the future, a response without `nextUpdate` is good for `max_age`
    after `thisUpdate`, nothing is good ten days after `thisUpdate`, and a
    `nextUpdate` that has passed ends it (RFC 6960 §3.2 asks for a recent
    `thisUpdate` and an unexpired `nextUpdate`).
    """
    if this_update > now + 300:
        return (
            "OCSPNotYetValid",
            f"OCSP response thisUpdate {format_time(this_update)} is in the future",
        )
    age = now - this_update
    if next_update is None and age > max_age:
        return (
            "OCSPStale",
            f"OCSP response thisUpdate {format_time(this_update)} is "
            f"{age / 3600:.0f} hours old and carries no nextUpdate; the limit is "
            f"{max_age / 3600:.0f} hours (RFC 6960 §3.2 requires a recent thisUpdate)",
        )
    if age > _MAX_LIFETIME_SECONDS:
        return (
            "OCSPStale",
            f"OCSP response thisUpdate {format_time(this_update)} is "
            "older than 10 days, whatever nextUpdate says",
        )
    if next_update is not None and next_update < now:
        return (
            "OCSPStale",
            f"OCSP response expired at {format_time(next_update)}",
        )
    return None


# --- OCSP ----------------------------------------------------------------------------


def find_issuer(
    leaf_der: bytes, candidates: list[bytes]
) -> tuple[bytes | None, str | None, str | None]:
    """The certificate among `candidates` that issued `leaf_der`, and how that was shown.

    A candidate must carry the leaf's issuer name and its key must verify the
    leaf's signature: anyone can mint a certificate with the right subject, so
    a name match alone binds nothing. Returns `(issuer, VERIFIED, None)` when
    the signature checks, `(issuer, UNSUPPORTED, why)` when the leaf is signed
    with an algorithm CertMonitor cannot verify and the name match is the best
    evidence available, and `(None, None, None)` when no candidate qualifies.
    """
    try:
        leaf = certinfo.certificate_signature_parts(leaf_der)  # type: ignore[attr-defined]
    except ValueError:
        return None, None, None
    fallback: tuple[bytes, str] | None = None
    for candidate in candidates:
        if candidate == leaf_der:
            continue
        try:
            if certinfo.ocsp_cert_id_inputs(leaf_der, candidate) is None:  # type: ignore[attr-defined]
                continue
            spki = certinfo.certificate_signature_parts(candidate)["spki"]  # type: ignore[attr-defined]
        except ValueError:
            continue
        outcome, problem = _signed_by(
            spki,
            leaf["signature_algorithm"],
            leaf["tbs"],
            leaf["signature"],
            leaf["signature_algorithm_params"],
        )
        if outcome == VERIFIED:
            return candidate, VERIFIED, None
        if outcome == UNSUPPORTED and fallback is None:
            fallback = (candidate, problem or "unsupported leaf signature algorithm")
    if fallback is None:
        return None, None, None
    return fallback[0], UNSUPPORTED, fallback[1]


def _bound_by_issuer(
    outcome: str, problem: str | None, binding: str | None, binding_problem: str | None
) -> tuple[str, str | None]:
    """Cap a signature outcome by how well the signer was tied to the leaf.

    A response verified under an issuer that is only name-matched to the leaf
    is not proof, because the name match could be satisfied by an impostor.
    """
    if outcome == VERIFIED and binding != VERIFIED:
        return UNSUPPORTED, (
            "the issuer certificate is only name-matched to the leaf "
            f"({binding_problem or 'its signature over the leaf could not be checked'})"
        )
    return outcome, problem


def build_ocsp_request(
    leaf_der: bytes, issuer_der: bytes
) -> tuple[bytes, dict[str, str]]:
    """Build a DER OCSPRequest for `leaf_der` and the CertID it asks about.

    Returns the request bytes and the expected `cert_id` fields
    (`issuer_name_hash`, `issuer_key_hash`, `serial_number` as hex) so the
    answer can be matched to the question.

    Raises:
        ValueError: If `issuer_der` did not issue `leaf_der`.
    """
    inputs = certinfo.ocsp_cert_id_inputs(leaf_der, issuer_der)  # type: ignore[attr-defined]
    if inputs is None:
        raise ValueError("the issuer certificate does not match the leaf's issuer")
    # SHA-1 is the CertID hash RFC 6960 responders expect; it only names the
    # issuer, so it carries no security weight here.
    name_hash = hashlib.sha1(inputs["issuer_name"], usedforsecurity=False).digest()
    key_hash = hashlib.sha1(inputs["issuer_key"], usedforsecurity=False).digest()
    serial = inputs["serial_number"]
    cert_id = _der(
        0x30,
        _der(0x30, _OID_SHA1 + b"\x05\x00")
        + _der(0x04, name_hash)
        + _der(0x04, key_hash)
        + _der(0x02, serial),
    )
    request = _der(0x30, _der(0x30, _der(0x30, _der(0x30, cert_id))))
    expected = {
        "issuer_name_hash": name_hash.hex(),
        "issuer_key_hash": key_hash.hex(),
        "serial_number": serial.hex(),
    }
    return request, expected


def _cert_id_matches(cert_id: dict[str, str], expected: dict[str, str]) -> bool:
    """Whether a response's CertID is the one the request asked about.

    All four fields must agree (RFC 6960 section 4.2.1): the hash algorithm the
    request used, both issuer hashes, and the serial. Leading zeros on the
    serial are ignored because some responders re-encode it.
    """
    return (
        cert_id["hash_algorithm"] == _SHA1_OID_TEXT
        and cert_id["issuer_name_hash"] == expected["issuer_name_hash"]
        and cert_id["issuer_key_hash"] == expected["issuer_key_hash"]
        and cert_id["serial_number"].lstrip("0")
        == expected["serial_number"].lstrip("0")
    )


def check_ocsp(
    leaf_der: bytes,
    issuer_der: bytes,
    url: str,
    *,
    timeout: float,
    proxy: ProxyConfig | None = None,
    now: float | None = None,
    issuer_binding: str = UNSUPPORTED,
    binding_problem: str | None = None,
    max_age: float = _OCSP_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Ask `url` about `leaf_der` and return one answer dict.

    The answer's `status` is `good`, `revoked`, or `unknown` when the
    responder answered about this certificate, and `error` otherwise, with
    `reason` saying why. What is cached is the responder's evidence: an
    answer whose signature verified under the issuer, kept until its
    `nextUpdate`, never longer than a day, never past `thisUpdate` plus ten
    days, and never past the `notAfter` of a delegated responder certificate
    that signed it; an answer with no `nextUpdate` is kept for at most an
    hour and never past `thisUpdate` plus `max_age`. Failed or unverifiable answers
    are fetched again next time. Every answer, cached or fresh, is then
    capped by how well this call's leaf is bound to the issuer
    (`issuer_binding`), so a cache hit never inherits an earlier caller's
    binding.
    """
    now = time.time() if now is None else now
    request, expected = build_ocsp_request(leaf_der, issuer_der)
    key = (
        url,
        expected["issuer_name_hash"],
        expected["issuer_key_hash"],
        expected["serial_number"],
    )
    cached = OCSP_CACHE.get(key, now)
    if (
        cached is not None
        and _ocsp_freshness_problem(
            cached["_this_update"], cached.get("_next_update"), now, max_age
        )
        is None
        and (cached.get("_valid_until") is None or cached["_valid_until"] > now)
    ):
        return _bound_answer(cached, issuer_binding, binding_problem, cached=True)
    answer = _ask_ocsp(
        request,
        expected,
        url,
        issuer_der,
        timeout=timeout,
        proxy=proxy,
        now=now,
        max_age=max_age,
    )
    if answer.get("verification") == VERIFIED:
        expires_at = _expiry_for(
            answer["_this_update"], answer.get("_next_update"), now, max_age
        )
        if answer.get("_valid_until") is not None:
            # A delegated responder's signature is only evidence while its
            # certificate is valid (RFC 6960 §4.2.2.2), so the cache cannot
            # outlive that either.
            expires_at = min(expires_at, float(answer["_valid_until"]))
        OCSP_CACHE.put(key, answer, expires_at)
    return _bound_answer(answer, issuer_binding, binding_problem, cached=False)


def _bound_answer(
    answer: dict[str, Any],
    binding: str | None,
    binding_problem: str | None,
    *,
    cached: bool,
) -> dict[str, Any]:
    """`answer` with its verification capped by this leaf's issuer binding."""
    bound = {**answer, "cached": cached}
    if "verification" not in answer:
        return bound
    outcome, problem = _bound_by_issuer(
        answer["verification"],
        answer.get("verification_error"),
        binding,
        binding_problem,
    )
    bound["signature_verified"] = outcome == VERIFIED
    bound["verification"] = outcome
    bound.pop("verification_error", None)
    if problem is not None:
        bound["verification_error"] = problem
    return bound


def _ask_ocsp(
    request: bytes,
    expected: dict[str, str],
    url: str,
    issuer_der: bytes,
    *,
    timeout: float,
    proxy: ProxyConfig | None,
    now: float,
    max_age: float,
) -> dict[str, Any]:
    """Fetch and verify one response; the outcome is the responder's alone.

    `verification` here says whether the response is signed by the issuer or
    an authorized responder. Binding that to the leaf is `check_ocsp`'s job.
    """
    answer: dict[str, Any] = {
        "method": "ocsp",
        "url": url,
        "signature_verified": False,
    }
    try:
        body = http.fetch(
            url,
            timeout=timeout,
            proxy=proxy,
            method="POST",
            body=request,
            content_type=OCSP_CONTENT_TYPE,
            accept=OCSP_RESPONSE_TYPE,
        )
        parsed = certinfo.parse_ocsp_response(body)  # type: ignore[attr-defined]
    except (OSError, ValueError) as exc:
        answer.update(status="error", error=type(exc).__name__, reason=str(exc))
        return answer
    if parsed["response_status"] != "successful":
        answer.update(
            status="error",
            error="OCSPResponderError",
            reason=f"OCSP responder answered {parsed['response_status']}",
        )
        return answer
    single = None
    for candidate in parsed["responses"]:
        if _cert_id_matches(candidate["cert_id"], expected):
            single = candidate
            break
    if single is None:
        answer.update(
            status="error",
            error="OCSPMismatch",
            reason="OCSP response does not cover the certificate that was asked about",
        )
        return answer
    freshness_problem = _ocsp_freshness_problem(
        single["this_update"], single["next_update"], now, max_age
    )
    if freshness_problem is not None:
        error, reason = freshness_problem
        answer.update(status="error", error=error, reason=reason)
        return answer
    outcome, problem, valid_until = _verify_ocsp_signer(
        parsed, issuer_der, expected["issuer_key_hash"], now
    )
    answer["signature_verified"] = outcome == VERIFIED
    answer["verification"] = outcome
    if problem is not None:
        answer["verification_error"] = problem
    answer.update(
        status=single["status"],
        produced_at=format_time(parsed["produced_at"]),
        this_update=format_time(single["this_update"]),
        next_update=format_time(single["next_update"]),
        revocation_time=format_time(single["revocation_time"]),
        revocation_reason=single["revocation_reason"],
        responder_key_hash=parsed["responder_key_hash"],
        responder_name=parsed["responder_name"],
        _next_update=single["next_update"],
        _this_update=single["this_update"],
        _valid_until=valid_until,
    )
    return answer


def _signed_by(
    signer_spki: bytes,
    algorithm: str,
    tbs: bytes,
    signature: bytes,
    params: bytes | None = None,
) -> tuple[str, str | None]:
    """Check one signature; see `certmonitor.signatures.verify` for the outcomes."""
    return verify_signature_bytes(signer_spki, algorithm, params, tbs, signature)


def verify_ocsp_response(
    parsed: dict[str, Any], issuer_der: bytes, issuer_key_hash: str, now: float
) -> tuple[str, str | None]:
    """Verify a parsed OCSP response against the certificate's issuer.

    The response is accepted when it is signed by the issuer itself, or by a
    responder certificate that the issuer signed, that carries the OCSP
    signing extended key usage, and that is valid at `now` (RFC 6960 §4.2.2.2).

    Returns `(VERIFIED, None)`; `(UNSUPPORTED, why)` when the signature uses
    an algorithm CertMonitor cannot check; or `(FAILED, why)` when the
    signature is wrong or the signer is not authorized. A failed response is
    not evidence of anything and must not be trusted either way.
    """
    outcome, problem, _ = _verify_ocsp_signer(parsed, issuer_der, issuer_key_hash, now)
    return outcome, problem


def _verify_ocsp_signer(
    parsed: dict[str, Any], issuer_der: bytes, issuer_key_hash: str, now: float
) -> tuple[str, str | None, int | None]:
    """`verify_ocsp_response`, plus when the signer stops being one.

    The third value is the delegated responder certificate's `notAfter`,
    after which its signature is no longer evidence and a cached answer must
    not be reused; `None` when the issuer signed the response itself.
    """
    issuer = certinfo.certificate_signature_parts(issuer_der)  # type: ignore[attr-defined]
    algorithm = parsed["signature_algorithm"]
    tbs = parsed["tbs_response_data"]
    signature = parsed["signature"]
    if not tbs or not signature or algorithm is None:
        return FAILED, "response carries no signature", None

    def names_issuer(name_der: bytes | None, key_hash: str | None) -> bool:
        return name_der == issuer["subject_der"] or key_hash == issuer_key_hash

    params = parsed["signature_algorithm_params"]
    if names_issuer(parsed["responder_name_der"], parsed["responder_key_hash"]):
        return (*_signed_by(issuer["spki"], algorithm, tbs, signature, params), None)

    for cert_der in parsed["certs"]:
        try:
            responder = certinfo.certificate_signature_parts(cert_der)  # type: ignore[attr-defined]
        except ValueError:
            continue
        key_hash = hashlib.sha1(
            responder["key_bits"], usedforsecurity=False
        ).hexdigest()
        if not names_issuer(responder["subject_der"], key_hash) and not (
            parsed["responder_name_der"] == responder["subject_der"]
            or parsed["responder_key_hash"] == key_hash
        ):
            continue
        if responder["issuer_der"] != issuer["subject_der"]:
            return (
                FAILED,
                "responder certificate was not issued by the certificate's CA",
                None,
            )
        if _OID_OCSP_SIGNING not in responder["extended_key_usage"]:
            return (
                FAILED,
                "responder certificate lacks the OCSP signing extended key usage",
                None,
            )
        if not responder["not_before"] <= now <= responder["not_after"]:
            return FAILED, "responder certificate is not currently valid", None
        outcome, problem = _signed_by(
            issuer["spki"],
            responder["signature_algorithm"],
            responder["tbs"],
            responder["signature"],
            responder["signature_algorithm_params"],
        )
        if outcome != VERIFIED:
            return outcome, f"responder certificate: {problem}", None
        outcome, problem = _signed_by(
            responder["spki"], algorithm, tbs, signature, params
        )
        return outcome, problem, int(responder["not_after"])
    return (
        FAILED,
        "response is not signed by the issuer or an authorized responder",
        None,
    )


# --- CRL -----------------------------------------------------------------------------


def fetch_crl(
    url: str,
    *,
    timeout: float,
    proxy: ProxyConfig | None = None,
    now: float | None = None,
) -> tuple[bytes, dict[str, Any], bool]:
    """Fetch and parse the CRL at `url`, reusing a remembered copy until its nextUpdate.

    Returns the DER bytes, the parsed summary from `certinfo.crl_info`, and
    whether the copy came from the cache. PEM CRLs are converted. Nothing is
    cached here: a CRL enters the cache through `remember_crl` once its
    signature has verified, so a corrupted or forged copy is fetched again
    next time rather than pinned until its `nextUpdate`.

    Raises:
        OSError: If the CRL cannot be fetched.
        ValueError: If the body is not a CRL.
    """
    now = time.time() if now is None else now
    cached = CRL_CACHE.get(url, now)
    if cached is not None and _still_current(cached[1].get("next_update"), now):
        der, info = cached
        return der, info, True
    body = http.fetch(url, timeout=timeout, proxy=proxy, accept="application/pkix-crl")
    der = pem_to_der(body) if body.lstrip().startswith(b"-----BEGIN") else body
    info = certinfo.crl_info(der)  # type: ignore[attr-defined]
    return der, info, False


def remember_crl(
    url: str, der: bytes, info: dict[str, Any], *, now: float | None = None
) -> None:
    """Cache a verified CRL until its `nextUpdate`, never longer than a day.

    A CRL without `nextUpdate` is kept for an hour, and never past the ten
    days after `thisUpdate` at which `_check_one_crl` stops accepting one.
    Unlike an OCSP response, a CRL with a `nextUpdate` is good however old
    its `thisUpdate` is, so that ceiling does not apply here. Call this only
    once the CRL's signature has verified under its issuer; the cache holds
    evidence, not fetch results.
    """
    now = time.time() if now is None else now
    if not _still_current(info["next_update"], now):
        return
    if info["next_update"] is None:
        expires_at = min(
            now + _DEFAULT_TTL_SECONDS, info["this_update"] + _MAX_LIFETIME_SECONDS
        )
    else:
        expires_at = min(float(info["next_update"]), now + _CACHE_CEILING_SECONDS)
    CRL_CACHE.put(url, (der, info), expires_at)


# --- evidence ------------------------------------------------------------------------


def _crl_scope_problem(info: dict[str, Any], url: str) -> str | None:
    """Why this CRL cannot answer for an end-entity certificate, or `None`.

    A delta CRL lists only changes since a base CRL, and an issuing
    distribution point can narrow a CRL to some reasons, to CA or attribute
    certificates, or to another issuer's certificates (RFC 5280 §5.2.4 and
    §5.2.5). A serial missing from such a list proves nothing. When the
    issuing distribution point names a location, RFC 5280 §6.3.3 step (b)(1)
    requires that location to be the one the certificate points to; since
    CertMonitor only ever fetches the URL taken from the certificate, that
    means the CRL's own named location must be `url`.
    """
    if info.get("delta_crl_indicator"):
        return "the CRL is a delta CRL that lists only changes since a base CRL"
    scope = info.get("issuing_distribution_point")
    if not scope:
        return None
    if scope.get("indirect_crl"):
        return "the CRL is an indirect CRL issued on behalf of another CA"
    if scope.get("only_some_reasons"):
        return "the CRL covers only some revocation reasons"
    if scope.get("only_contains_ca_certs"):
        return "the CRL covers only CA certificates"
    if scope.get("only_contains_attribute_certs"):
        return "the CRL covers only attribute certificates"
    uris = scope.get("distribution_point_uris") or []
    if uris or scope.get("names_other_locations"):
        if any(_same_location(uri, url) for uri in uris):
            return None
        if uris:
            return (
                "the CRL's issuing distribution point names "
                f"{', '.join(uris)}, not the location it was fetched from "
                "(RFC 5280 section 6.3.3)"
            )
        return (
            "the CRL's issuing distribution point names only locations that are "
            "not URLs, so it cannot be matched to the location it was fetched from "
            "(RFC 5280 section 6.3.3)"
        )
    return None


def _same_location(left: str, right: str) -> bool:
    """Whether two URLs name the same resource; scheme and host compare case-insensitively, and an empty path counts as `/`."""
    a, b = urlsplit(left), urlsplit(right)
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.netloc or "").lower() == (b.netloc or "").lower()
        and (a.path or "/") == (b.path or "/")
        and a.query == b.query
    )


class RevocationEvidence:
    """What the OCSP responder and the CRL say about one certificate.

    Built once per `validate()` call by the monitor and handed to the
    `revocation` validator as its data source. Each method fetches on first
    use and remembers its answer, so asking twice costs nothing.
    """

    def __init__(
        self,
        *,
        leaf_der: bytes,
        chain_der: list[bytes],
        cert_info: dict[str, Any],
        timeout: float,
        proxy: ProxyConfig | None = None,
        offline: bool = False,
    ) -> None:
        self.leaf_der = leaf_der
        self.offline = offline
        self.chain_der = list(chain_der)
        self.cert_info = cert_info
        self.timeout = timeout
        self.proxy = proxy
        self.ocsp_max_age: float = _OCSP_MAX_AGE_SECONDS
        self.ocsp_urls = http_urls(cert_info.get("OCSP"))
        self.crl_urls = http_urls(cert_info.get("crlDistributionPoints"))
        self.issuer_urls = http_urls(cert_info.get("caIssuers"))
        self._issuer: bytes | None = None
        self._issuer_error: str | None = None
        self._issuer_binding: str | None = None
        self._binding_problem: str | None = None
        self._answers: dict[str, dict[str, Any]] = {}

    def answer(self, method: str) -> dict[str, Any]:
        """The answer for `method` (`ocsp` or `crl`), fetched on first use."""
        if method not in self._answers:
            self._answers[method] = self.ocsp() if method == "ocsp" else self.crl()
        return self._answers[method]

    def issuer(self) -> bytes | None:
        """The issuer certificate: from the collected chain, else from the AIA pointer.

        Only a certificate whose key verifies the leaf's signature qualifies.
        `_issuer_binding` records whether that check ran (`VERIFIED`) or the
        leaf's algorithm is one CertMonitor cannot check (`UNSUPPORTED`).
        """
        if self._issuer is not None or self._issuer_error is not None:
            return self._issuer
        found, binding, problem = find_issuer(
            self.leaf_der, self.chain_der[1:] + self.chain_der[:1]
        )
        if found is None:
            for url in self.issuer_urls:
                try:
                    body = http.fetch(
                        url,
                        timeout=self.timeout,
                        proxy=self.proxy,
                        accept=CA_ISSUERS_ACCEPT,
                    )
                except OSError as exc:
                    self._issuer_error = (
                        f"could not fetch the issuer certificate: {exc}"
                    )
                    continue
                # RFC 5280 §4.2.2.1: the pointer may serve one certificate or
                # a certs-only PKCS#7 bundle, in DER or PEM either way.
                try:
                    candidates = bundles.certificates_from_bytes(body).certificates
                except ValueError as exc:
                    self._issuer_error = (
                        f"the caIssuers pointer did not return a certificate: {exc}"
                    )
                    continue
                found, binding, problem = find_issuer(self.leaf_der, candidates)
                if found is not None:
                    self._issuer_error = None
                    break
                self._issuer_error = (
                    "the certificate fetched from the caIssuers pointer did not "
                    "sign this certificate"
                )
        if found is None and self._issuer_error is None:
            self._issuer_error = (
                "no certificate in the chain signed this certificate and it has "
                "no AIA pointer"
            )
        self._issuer = found
        self._issuer_binding = binding
        self._binding_problem = problem
        return found

    def ocsp(self) -> dict[str, Any]:
        if "ocsp" in self._answers:
            return self._answers["ocsp"]
        if self.offline:
            return self._remember("ocsp", self._offline("ocsp"))
        if not self.ocsp_urls:
            return self._remember(
                "ocsp",
                {
                    "method": "ocsp",
                    "status": "unsupported",
                    "reason": "the certificate carries no OCSP responder URL",
                },
            )
        issuer = self.issuer()
        if issuer is None:
            return self._remember(
                "ocsp",
                {
                    "method": "ocsp",
                    "status": "error",
                    "error": "MissingIssuer",
                    "reason": self._issuer_error or "issuer certificate unavailable",
                },
            )
        last: dict[str, Any] = {}
        for url in self.ocsp_urls:
            last = check_ocsp(
                self.leaf_der,
                issuer,
                url,
                timeout=self.timeout,
                proxy=self.proxy,
                issuer_binding=self._issuer_binding or UNSUPPORTED,
                binding_problem=self._binding_problem,
                max_age=self.ocsp_max_age,
            )
            if last["status"] != "error" and last.get("verification") != FAILED:
                break
        return self._remember("ocsp", last)

    def crl(self) -> dict[str, Any]:
        if "crl" in self._answers:
            return self._answers["crl"]
        if self.offline:
            return self._remember("crl", self._offline("crl"))
        if not self.crl_urls:
            return self._remember(
                "crl",
                {
                    "method": "crl",
                    "status": "unsupported",
                    "reason": "the certificate carries no CRL distribution point",
                },
            )
        last: dict[str, Any] = {}
        for url in self.crl_urls:
            last = self._check_one_crl(url)
            if last["status"] != "error" and last.get("verification") != FAILED:
                break
        return self._remember("crl", last)

    def _check_one_crl(self, url: str) -> dict[str, Any]:
        """Fetch one CRL, verify it against the bound issuer, and look the leaf up.

        Before the list is consulted the CRL must be in scope for the leaf,
        carry no critical extension CertMonitor cannot process (RFC 5280
        §5.2, §5.3), name the bound issuer, come from an issuer whose
        `keyUsage`, if present, allows `cRLSign` (§6.3.3 step (f)), and
        carry that issuer's signature. Only a CRL whose signature verified
        is cached. The validator discards any answer whose signature failed.
        No second connection is opened, so the verdict can only ever describe
        the certificate that was collected.
        """
        answer: dict[str, Any] = {
            "method": "crl",
            "url": url,
            "signature_verified": False,
        }
        try:
            der, info, cached = fetch_crl(url, timeout=self.timeout, proxy=self.proxy)
        except (OSError, ValueError) as exc:
            answer.update(status="error", error=type(exc).__name__, reason=str(exc))
            return answer
        answer.update(
            cached=cached,
            this_update=format_time(info["this_update"]),
            next_update=format_time(info["next_update"]),
            revoked_count=info["revoked_count"],
        )
        now = time.time()
        if info["this_update"] > now + 300:
            answer.update(
                status="error",
                error="CRLNotYetValid",
                reason=f"CRL thisUpdate {answer['this_update']} is in the future",
            )
            return answer
        if info["next_update"] is not None and info["next_update"] < now:
            answer.update(
                status="error",
                error="CRLStale",
                reason=f"CRL expired at {answer['next_update']}",
            )
            return answer
        if (
            info["next_update"] is None
            and now - info["this_update"] > _MAX_LIFETIME_SECONDS
        ):
            answer.update(
                status="error",
                error="CRLStale",
                reason=(
                    f"CRL thisUpdate {answer['this_update']} is older than 10 days "
                    "and carries no nextUpdate"
                ),
            )
            return answer
        scope_problem = _crl_scope_problem(info, url)
        if scope_problem is not None:
            answer.update(
                status="error",
                error="CRLScopeUnsupported",
                reason=f"{scope_problem}; the certificate's status cannot be read from it",
            )
            return answer
        unsupported = info.get("unsupported_critical_extensions") or []
        if unsupported:
            answer.update(
                status="error",
                error="CRLUnsupportedCriticalExtension",
                reason=(
                    "the CRL carries a critical extension CertMonitor cannot "
                    f"process ({', '.join(unsupported)}); RFC 5280 sections 5.2 "
                    "and 5.3 forbid using it to determine certificate status"
                ),
            )
            return answer
        issuer = self.issuer()
        if issuer is None:
            answer.update(
                status="error",
                error="MissingIssuer",
                reason=self._issuer_error or "issuer certificate unavailable",
            )
            return answer
        parts = certinfo.certificate_signature_parts(issuer)  # type: ignore[attr-defined]
        if info["issuer_der"] != parts["subject_der"]:
            answer.update(
                status="error",
                error="CRLIssuerMismatch",
                reason="the CRL was not issued by the certificate's CA",
            )
            return answer
        key_usage = parts.get("key_usage")
        if key_usage is not None and "crl_sign" not in key_usage:
            answer.update(
                status="error",
                error="CRLSignerNotAuthorized",
                reason=(
                    "the issuer certificate's keyUsage does not include cRLSign, "
                    "so it may not sign CRLs (RFC 5280 section 6.3.3)"
                ),
            )
            return answer
        outcome, problem = _signed_by(
            parts["spki"],
            info["signature_algorithm"],
            info["tbs_cert_list"],
            info["signature"],
            info["signature_algorithm_params"],
        )
        if outcome == VERIFIED and not cached:
            remember_crl(url, der, info, now=now)
        outcome, problem = _bound_by_issuer(
            outcome, problem, self._issuer_binding, self._binding_problem
        )
        answer["signature_verified"] = outcome == VERIFIED
        answer["verification"] = outcome
        if problem is not None:
            answer["verification_error"] = problem
        serial = certinfo.ocsp_cert_id_inputs(self.leaf_der, issuer)["serial_number"]  # type: ignore[attr-defined]
        entry = certinfo.crl_lookup(der, serial)  # type: ignore[attr-defined]
        if entry is None:
            answer["status"] = "good"
        else:
            answer.update(
                status="revoked",
                revocation_time=format_time(entry["revocation_time"]),
                revocation_reason=entry["revocation_reason"],
            )
        return answer

    @staticmethod
    def _offline(method: str) -> dict[str, Any]:
        return {
            "method": method,
            "status": "unsupported",
            "reason": f"{method.upper()} checking requires a live connection; "
            "this certificate was loaded from a file.",
        }

    def _remember(self, method: str, answer: dict[str, Any]) -> dict[str, Any]:
        self._answers[method] = answer
        return answer
