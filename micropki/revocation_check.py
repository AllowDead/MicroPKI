"""Client-side CRL and OCSP revocation checks."""

from __future__ import annotations

import datetime as _dt
import urllib.request
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


@dataclass
class RevocationStatus:
    status: str
    source: str
    reason: Optional[str] = None
    revocation_time: Optional[str] = None
    detail: str = ""


def _load_url_or_file(location: str) -> bytes:
    if location.startswith("http://") or location.startswith("https://"):
        with urllib.request.urlopen(location, timeout=5) as resp:
            return resp.read()
    with open(location, "rb") as f:
        return f.read()


def load_crl_from_location(location: str) -> x509.CertificateRevocationList:
    data = _load_url_or_file(location)
    if b"-----BEGIN" in data[:100]:
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def check_crl(cert: x509.Certificate, issuer_cert: x509.Certificate, crl_location: str, validation_time: _dt.datetime | None = None) -> RevocationStatus:
    crl = load_crl_from_location(crl_location)
    if crl.issuer != issuer_cert.subject:
        raise ValueError("CRL issuer does not match issuer certificate")
    if not crl.is_signature_valid(issuer_cert.public_key()):
        raise ValueError("CRL signature verification failed")
    now = validation_time or _dt.datetime.now(_dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    detail = ""
    if crl.next_update_utc and crl.next_update_utc < now:
        detail = "warning: CRL nextUpdate is in the past"
    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            reason = None
            try:
                reason = revoked.extensions.get_extension_for_oid(ExtensionOID.CRL_REASON).value.reason.name
            except Exception:
                pass
            return RevocationStatus("revoked", "crl", reason, revoked.revocation_date_utc.isoformat().replace("+00:00", "Z"), detail)
    return RevocationStatus("good", "crl", detail=detail)


def extract_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def extract_crl_distribution_point(cert: x509.Certificate) -> Optional[str]:
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return None
    for point in cdp:
        if point.full_name:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    return name.value
    return None


def check_ocsp(cert: x509.Certificate, issuer_cert: x509.Certificate, ocsp_url: str, nonce: bytes | None = b"micropki-client") -> RevocationStatus:
    builder = crypto_ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA1())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    request = builder.build().public_bytes(serialization.Encoding.DER)
    http_req = urllib.request.Request(
        ocsp_url,
        data=request,
        headers={"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"},
        method="POST",
    )
    with urllib.request.urlopen(http_req, timeout=5) as resp:
        data = resp.read()
    response = crypto_ocsp.load_der_ocsp_response(data)
    if response.response_status != crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError(f"OCSP responder returned {response.response_status.name}")
    if nonce is not None:
        echoed = response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        if echoed != nonce:
            raise ValueError("OCSP nonce mismatch")
    status = response.certificate_status
    if status == crypto_ocsp.OCSPCertStatus.GOOD:
        return RevocationStatus("good", "ocsp")
    if status == crypto_ocsp.OCSPCertStatus.REVOKED:
        reason = response.revocation_reason.name if response.revocation_reason else None
        revoked_at = response.revocation_time_utc.isoformat().replace("+00:00", "Z") if response.revocation_time_utc else None
        return RevocationStatus("revoked", "ocsp", reason, revoked_at)
    return RevocationStatus("unknown", "ocsp")


def check_status_with_fallback(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl: str | None = None,
    ocsp_url: str | None = None,
    logger=None,
) -> RevocationStatus:
    ocsp_target = ocsp_url or extract_ocsp_url(cert)
    if ocsp_target:
        try:
            status = check_ocsp(cert, issuer_cert, ocsp_target)
            if status.status in {"good", "revoked"}:
                return status
            if logger:
                logger.warning("OCSP returned unknown; falling back to CRL")
        except Exception as exc:
            if logger:
                logger.warning(f"OCSP check failed; falling back to CRL: {exc}")
    crl_target = crl or extract_crl_distribution_point(cert)
    if crl_target:
        try:
            return check_crl(cert, issuer_cert, crl_target)
        except Exception as exc:
            if logger:
                logger.warning(f"CRL check failed: {exc}")
            return RevocationStatus("unknown", "crl", detail=str(exc))
    return RevocationStatus("unknown", "none", detail="No OCSP responder or CRL was available")
