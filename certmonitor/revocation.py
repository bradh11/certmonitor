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
CRLs are fetched here and judged by OpenSSL: the monitor loads the CRL into
a verifying TLS context, so a `good` or `revoked` CRL answer is backed by
OpenSSL's signature and validity checks.

Fetched CRLs and OCSP answers are cached process-wide until their
`nextUpdate`, so a fleet scan downloads each CA's CRL once. A monitor built
from a file never touches the network, so both methods report `unsupported`
for it.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from certmonitor import certinfo
from certmonitor.protocol_handlers import http
from certmonitor.protocol_handlers.proxy import ProxyConfig

METHODS = ("ocsp", "crl")
OCSP_CONTENT_TYPE = "application/ocsp-request"
OCSP_RESPONSE_TYPE = "application/ocsp-response"

_OID_SHA1 = b"\x06\x05\x2b\x0e\x03\x02\x1a"
_OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
_CACHE_CEILING_SECONDS = 24 * 60 * 60
_DEFAULT_TTL_SECONDS = 60 * 60
_CACHE_LIMIT = 256

CrlCheck = Callable[[bytes], dict[str, Any]]


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


def serial_bytes(serial_hex: str) -> bytes:
    """The raw INTEGER bytes of a serial number rendered as hex."""
    digits = serial_hex.replace(":", "")
    if len(digits) % 2:
        digits = "0" + digits
    return bytes.fromhex(digits)


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


def _expiry_for(next_update: int | None, now: float) -> float:
    """When a fetched answer stops being reusable.

    Never later than the answer's own `nextUpdate`: a cache must not extend
    the validity of signed evidence. Capped at a day for answers that promise
    more, and an hour for answers that carry no `nextUpdate` at all.
    """
    if next_update is None:
        return now + _DEFAULT_TTL_SECONDS
    return min(float(next_update), now + _CACHE_CEILING_SECONDS)


def _still_current(next_update: int | None, now: float) -> bool:
    return next_update is None or next_update > now


# --- OCSP ----------------------------------------------------------------------------


def find_issuer(leaf_der: bytes, candidates: list[bytes]) -> bytes | None:
    """The certificate among `candidates` that issued `leaf_der`, if any."""
    for candidate in candidates:
        if candidate == leaf_der:
            continue
        try:
            if certinfo.ocsp_cert_id_inputs(leaf_der, candidate) is not None:  # type: ignore[attr-defined]
                return candidate
        except ValueError:
            continue
    return None


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


def check_ocsp(
    leaf_der: bytes,
    issuer_der: bytes,
    url: str,
    *,
    timeout: float,
    proxy: ProxyConfig | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Ask `url` about `leaf_der` and return one answer dict.

    The answer's `status` is `good`, `revoked`, or `unknown` when the
    responder answered about this certificate, and `error` otherwise, with
    `reason` saying why. Answers are cached until their `nextUpdate`.
    """
    now = time.time() if now is None else now
    request, expected = build_ocsp_request(leaf_der, issuer_der)
    key = (url, expected["issuer_key_hash"], expected["serial_number"])
    cached = OCSP_CACHE.get(key, now)
    if cached is not None and _still_current(cached.get("_next_update"), now):
        return {**cached, "cached": True}
    answer = _ask_ocsp(
        request, expected, url, issuer_der, timeout=timeout, proxy=proxy, now=now
    )
    if answer["status"] in ("good", "revoked", "unknown") and _still_current(
        answer.get("_next_update"), now
    ):
        OCSP_CACHE.put(key, answer, _expiry_for(answer.get("_next_update"), now))
    return {**answer, "cached": False}


def _ask_ocsp(
    request: bytes,
    expected: dict[str, str],
    url: str,
    issuer_der: bytes,
    *,
    timeout: float,
    proxy: ProxyConfig | None,
    now: float,
) -> dict[str, Any]:
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
        cert_id = candidate["cert_id"]
        if cert_id["issuer_key_hash"] == expected["issuer_key_hash"] and cert_id[
            "serial_number"
        ].lstrip("0") == expected["serial_number"].lstrip("0"):
            single = candidate
            break
    if single is None:
        answer.update(
            status="error",
            error="OCSPMismatch",
            reason="OCSP response does not cover the certificate that was asked about",
        )
        return answer
    if single["this_update"] > now + 300:
        answer.update(
            status="error",
            error="OCSPNotYetValid",
            reason=f"OCSP response thisUpdate {format_time(single['this_update'])} is in the future",
        )
        return answer
    if single["next_update"] is not None and single["next_update"] < now:
        answer.update(
            status="error",
            error="OCSPStale",
            reason=f"OCSP response expired at {format_time(single['next_update'])}",
        )
        return answer
    outcome, problem = verify_ocsp_response(
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
    )
    return answer


VERIFIED = "verified"
UNSUPPORTED = "unsupported"
FAILED = "failed"


def _signed_by(
    signer_spki: bytes, algorithm: str, tbs: bytes, signature: bytes
) -> tuple[str, str | None]:
    """Check one signature.

    Returns `(VERIFIED, None)`, `(UNSUPPORTED, why)` when the algorithm or key
    is one CertMonitor cannot check, or `(FAILED, why)` when the check ran and
    the signature is wrong.
    """
    hash_name = certinfo.signature_hash(algorithm)  # type: ignore[attr-defined]
    if hash_name is None:
        return UNSUPPORTED, f"unsupported signature algorithm {algorithm}"
    digest = hashlib.new(hash_name, tbs).digest()
    try:
        ok = certinfo.verify_signature(  # type: ignore[attr-defined]
            algorithm, digest, signature, signer_spki
        )
    except ValueError as exc:
        outcome = UNSUPPORTED if str(exc).startswith("unsupported") else FAILED
        return outcome, str(exc)
    return (VERIFIED, None) if ok else (FAILED, "signature does not verify")


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
    issuer = certinfo.certificate_signature_parts(issuer_der)  # type: ignore[attr-defined]
    algorithm = parsed["signature_algorithm"]
    tbs = parsed["tbs_response_data"]
    signature = parsed["signature"]
    if not tbs or not signature or algorithm is None:
        return FAILED, "response carries no signature"

    def names_issuer(name_der: bytes | None, key_hash: str | None) -> bool:
        return name_der == issuer["subject_der"] or key_hash == issuer_key_hash

    if names_issuer(parsed["responder_name_der"], parsed["responder_key_hash"]):
        return _signed_by(issuer["spki"], algorithm, tbs, signature)

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
            )
        if _OID_OCSP_SIGNING not in responder["extended_key_usage"]:
            return (
                FAILED,
                "responder certificate lacks the OCSP signing extended key usage",
            )
        if not responder["not_before"] <= now <= responder["not_after"]:
            return FAILED, "responder certificate is not currently valid"
        outcome, problem = _signed_by(
            issuer["spki"],
            responder["signature_algorithm"],
            responder["tbs"],
            responder["signature"],
        )
        if outcome != VERIFIED:
            return outcome, f"responder certificate: {problem}"
        return _signed_by(responder["spki"], algorithm, tbs, signature)
    return FAILED, "response is not signed by the issuer or an authorized responder"


# --- CRL -----------------------------------------------------------------------------


def fetch_crl(
    url: str,
    *,
    timeout: float,
    proxy: ProxyConfig | None = None,
    now: float | None = None,
) -> tuple[bytes, dict[str, Any], bool]:
    """Fetch and parse the CRL at `url`, reusing a cached copy until its nextUpdate.

    Returns the DER bytes, the parsed summary from `certinfo.crl_info`, and
    whether the copy came from the cache. PEM CRLs are converted.

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
    if _still_current(info["next_update"], now):
        CRL_CACHE.put(url, (der, info), _expiry_for(info["next_update"], now))
    return der, info, False


# --- evidence ------------------------------------------------------------------------


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
        crl_check: CrlCheck | None = None,
        offline: bool = False,
    ) -> None:
        self.leaf_der = leaf_der
        self.offline = offline
        self.chain_der = list(chain_der)
        self.cert_info = cert_info
        self.timeout = timeout
        self.proxy = proxy
        self.crl_check = crl_check
        self.ocsp_urls = http_urls(cert_info.get("OCSP"))
        self.crl_urls = http_urls(cert_info.get("crlDistributionPoints"))
        self.issuer_urls = http_urls(cert_info.get("caIssuers"))
        self._issuer: bytes | None = None
        self._issuer_error: str | None = None
        self._answers: dict[str, dict[str, Any]] = {}

    def answer(self, method: str) -> dict[str, Any]:
        """The answer for `method` (`ocsp` or `crl`), fetched on first use."""
        if method not in self._answers:
            self._answers[method] = self.ocsp() if method == "ocsp" else self.crl()
        return self._answers[method]

    def issuer(self) -> bytes | None:
        """The issuer certificate: from the collected chain, else from the AIA pointer."""
        if self._issuer is not None or self._issuer_error is not None:
            return self._issuer
        found = find_issuer(self.leaf_der, self.chain_der[1:] + self.chain_der[:1])
        if found is None:
            for url in self.issuer_urls:
                try:
                    body = http.fetch(url, timeout=self.timeout, proxy=self.proxy)
                except OSError as exc:
                    self._issuer_error = (
                        f"could not fetch the issuer certificate: {exc}"
                    )
                    continue
                if body.lstrip().startswith(b"-----BEGIN"):
                    body = pem_to_der(body)
                found = find_issuer(self.leaf_der, [body])
                if found is not None:
                    self._issuer_error = None
                    break
        if found is None and self._issuer_error is None:
            self._issuer_error = (
                "the issuer certificate is not in the chain and has no AIA pointer"
            )
        self._issuer = found
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
                self.leaf_der, issuer, url, timeout=self.timeout, proxy=self.proxy
            )
            if last["status"] != "error":
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
        if self.crl_check is None:
            return self._remember("crl", self._offline("crl"))
        last: dict[str, Any] = {}
        for url in self.crl_urls:
            last = self._check_one_crl(url)
            if last["status"] != "error":
                break
        return self._remember("crl", last)

    def _check_one_crl(self, url: str) -> dict[str, Any]:
        answer: dict[str, Any] = {
            "method": "crl",
            "url": url,
            "signature_verified": True,
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
        assert self.crl_check is not None
        verdict = self.crl_check(der)
        answer.update(verdict)
        if verdict.get("status") == "revoked":
            serial = self.cert_info.get("serialNumber")
            entry = (
                certinfo.crl_lookup(der, serial_bytes(serial))  # type: ignore[attr-defined]
                if serial
                else None
            )
            if entry is not None:
                answer.update(
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
