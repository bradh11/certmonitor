"""Certificate bundles: PEM, DER, and certs-only PKCS#7.

Certificates reach CertMonitor as files (`CertMonitor.from_file`), as bytes
(`CertMonitor.from_bytes`), and as the body a certificate's `caIssuers`
pointer serves. Each may be one or more PEM `CERTIFICATE` blocks, a PEM
`PKCS7` block, a DER certs-only PKCS#7 message (a `.p7b` or `.p7c`), or one
DER certificate. `certificates_from_bytes` tells them apart and hands back
DER certificates; `leaf_first` puts an unordered bundle into chain order.
"""

from __future__ import annotations

import base64
import re
import ssl
from typing import NamedTuple

from certmonitor import certinfo

_PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)
_PEM_PKCS7 = re.compile(rb"-----BEGIN PKCS7-----(.*?)-----END PKCS7-----", re.S)


class Bundle(NamedTuple):
    """The certificates found in some bytes and the encoding they came in."""

    certificates: list[bytes]
    kind: str
    """`pem`, `der`, or `pkcs7`."""


def certificates_from_bytes(data: bytes) -> Bundle:
    """Every certificate in `data`, as DER, in the order found.

    PEM `CERTIFICATE` blocks are taken as they stand. Otherwise a PEM `PKCS7`
    block, or DER that is a signedData ContentInfo, is unpacked as a
    certs-only PKCS#7 message. Anything else is passed through as one DER
    certificate for the X.509 parser to judge.

    Raises:
        ValueError: If `data` is empty, a PKCS#7 message is malformed, or a
            PKCS#7 message carries no certificates.
    """
    data = bytes(data)
    if not data.strip():
        raise ValueError("no certificate data")
    blocks = _PEM_CERTIFICATE.findall(data)
    if blocks:
        pems = [block.decode("ascii") + "\n" for block in blocks]
        return Bundle([ssl.PEM_cert_to_DER_cert(pem) for pem in pems], "pem")
    pkcs7_blocks = _PEM_PKCS7.findall(data)
    if pkcs7_blocks:
        found: list[bytes] = []
        for body in pkcs7_blocks:
            try:
                message = base64.b64decode(b"".join(body.split()), validate=True)
            except ValueError as exc:
                raise ValueError(f"not a PKCS#7 message: {exc}") from exc
            found.extend(_pkcs7_certificates(message))
        return Bundle(found, "pkcs7")
    if _is_content_info(data):
        return Bundle(_pkcs7_certificates(data), "pkcs7")
    return Bundle([data], "der")


def _pkcs7_certificates(message: bytes) -> list[bytes]:
    try:
        found = certinfo.pkcs7_certificates(message)  # type: ignore[attr-defined]
    except ValueError as exc:
        raise ValueError(f"not a PKCS#7 certificate bundle: {exc}") from exc
    if not found:
        raise ValueError("the PKCS#7 message carries no certificates")
    return list(found)


def _is_content_info(data: bytes) -> bool:
    """Whether `data` is a SEQUENCE whose first element is an OBJECT IDENTIFIER.

    That is the shape of a CMS ContentInfo; a Certificate's first element is
    the TBSCertificate SEQUENCE, so the two never look alike.
    """
    if len(data) < 2 or data[0] != 0x30:
        return False
    first_length = data[1]
    header = 2 if first_length < 0x80 else 2 + (first_length & 0x7F)
    return len(data) > header and data[header] == 0x06


def leaf_first(certificates: list[bytes]) -> list[bytes]:
    """`certificates` in chain order: the leaf, then each certificate's issuer.

    A PKCS#7 bundle carries no order. The leaf is the certificate that
    issued none of the others; when more than one qualifies, say a root and
    a leaf whose intermediate is missing, the one that is not a CA wins. A
    self-signed certificate that is not a CA is therefore a leaf like any
    other. From the leaf the chain follows issuer names as far as it can,
    and anything that does not chain keeps its place at the end. When no
    single leaf can be told apart, or something is not a certificate, the
    list comes back as given.
    """
    if len(certificates) < 2:
        return list(certificates)
    names: list[tuple[bytes, bytes]] = []
    is_ca: list[bool] = []
    for der in certificates:
        try:
            parts = certinfo.certificate_signature_parts(der)  # type: ignore[attr-defined]
        except ValueError:
            return list(certificates)
        names.append((parts["subject_der"], parts["issuer_der"]))
        is_ca.append(bool(parts["is_ca"]))
    leaves = [
        index
        for index, (subject, _) in enumerate(names)
        if not any(
            issuer == subject
            for other, (_, issuer) in enumerate(names)
            if other != index
        )
    ]
    if len(leaves) != 1:
        leaves = [index for index in leaves if not is_ca[index]]
    if len(leaves) != 1:
        return list(certificates)
    order = [leaves[0]]
    while True:
        _, wanted = names[order[-1]]
        parents = [
            index
            for index, (subject, _) in enumerate(names)
            if subject == wanted and index not in order
        ]
        if len(parents) != 1:
            break
        order.append(parents[0])
    order.extend(index for index in range(len(certificates)) if index not in order)
    return [certificates[index] for index in order]
