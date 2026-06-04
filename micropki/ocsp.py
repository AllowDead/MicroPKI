"""OCSP certificate issuance and response helpers for MicroPKI."""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .crypto_utils import name_to_string
from .database import get_certificate_by_serial, normalize_serial_hex
from .revocation import reason_to_flag

SUPPORTED_OCSP_HASHES = (hashes.SHA1, hashes.SHA256)


@dataclass(frozen=True)
class OCSPDecision:
    serial_hex: str
    status: str
    issuer_matched: bool


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_iso_datetime(value: str | None) -> Optional[_dt.datetime]:
    if not value:
        return None
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = _dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def _hash_name(algorithm: hashes.HashAlgorithm) -> str:
    name = algorithm.name.lower().replace("-", "")
    if name not in {"sha1", "sha256"}:
        raise ValueError("OCSP responder supports only SHA-1 and SHA-256 CertID hashes")
    return name


def _digest(data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    return hashlib.new(_hash_name(algorithm), data).digest()


def _issuer_public_key_bytes(cert: x509.Certificate) -> bytes:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1,
        )
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def issuer_hashes(ca_cert: x509.Certificate, algorithm: hashes.HashAlgorithm) -> tuple[bytes, bytes]:
    """Return OCSP issuerNameHash and issuerKeyHash for a CA certificate."""
    return (
        _digest(ca_cert.subject.public_bytes(), algorithm),
        _digest(_issuer_public_key_bytes(ca_cert), algorithm),
    )


def certid_matches_issuer(request: crypto_ocsp.OCSPRequest, ca_cert: x509.Certificate) -> bool:
    expected_name_hash, expected_key_hash = issuer_hashes(ca_cert, request.hash_algorithm)
    return request.issuer_name_hash == expected_name_hash and request.issuer_key_hash == expected_key_hash


def signing_hash_for_key(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384() if isinstance(private_key.curve, ec.SECP384R1) else hashes.SHA256()
    raise ValueError("Unsupported OCSP responder private key type")


def load_ocsp_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def validate_ocsp_signer_certificate(cert: x509.Certificate) -> None:
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if bc.ca:
        raise ValueError("OCSP responder certificate must have CA=FALSE")
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
        raise ValueError("OCSP responder certificate must use digitalSignature only for signing-related key usage")
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
        raise ValueError("OCSP responder certificate must include id-kp-OCSPSigning EKU")


def extract_nonce(request: crypto_ocsp.OCSPRequest) -> bytes | None:
    try:
        return request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        return None


def build_unsuccessful_response(status: crypto_ocsp.OCSPResponseStatus) -> bytes:
    return crypto_ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)


def determine_status(db_path: str, request: crypto_ocsp.OCSPRequest, ca_cert: x509.Certificate) -> tuple[crypto_ocsp.OCSPCertStatus, Optional[_dt.datetime], Optional[x509.ReasonFlags], OCSPDecision]:
    serial_hex = normalize_serial_hex(request.serial_number)
    issuer_ok = certid_matches_issuer(request, ca_cert)
    if not issuer_ok:
        return crypto_ocsp.OCSPCertStatus.UNKNOWN, None, None, OCSPDecision(serial_hex, "unknown", False)

    record = get_certificate_by_serial(db_path, serial_hex)
    ca_subject = name_to_string(ca_cert.subject)
    if not record or record.get("issuer") != ca_subject:
        return crypto_ocsp.OCSPCertStatus.UNKNOWN, None, None, OCSPDecision(serial_hex, "unknown", True)

    if record.get("status") == "revoked":
        revoked_at = _parse_iso_datetime(record.get("revocation_date")) or _utc_now()
        reason = reason_to_flag(record.get("revocation_reason") or "unspecified")
        return crypto_ocsp.OCSPCertStatus.REVOKED, revoked_at, reason, OCSPDecision(serial_hex, "revoked", True)

    return crypto_ocsp.OCSPCertStatus.GOOD, None, None, OCSPDecision(serial_hex, "good", True)


def build_ocsp_response(
    request: crypto_ocsp.OCSPRequest,
    db_path: str,
    ca_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    cache_ttl: int = 60,
) -> tuple[bytes, OCSPDecision]:
    validate_ocsp_signer_certificate(responder_cert)
    status, revocation_time, revocation_reason, decision = determine_status(db_path, request, ca_cert)
    now = _utc_now()
    next_update = now + _dt.timedelta(seconds=max(1, int(cache_ttl)))

    builder = crypto_ocsp.OCSPResponseBuilder()
    builder = builder.add_response_by_hash(
        request.issuer_name_hash,
        request.issuer_key_hash,
        request.serial_number,
        request.hash_algorithm,
        status,
        now,
        next_update,
        revocation_time,
        revocation_reason,
    )
    builder = builder.responder_id(crypto_ocsp.OCSPResponderEncoding.HASH, responder_cert)
    builder = builder.certificates([responder_cert])
    nonce = extract_nonce(request)
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    response = builder.sign(responder_key, signing_hash_for_key(responder_key))
    return response.public_bytes(serialization.Encoding.DER), decision


def parse_ocsp_request(data: bytes) -> crypto_ocsp.OCSPRequest:
    request = crypto_ocsp.load_der_ocsp_request(data)
    _hash_name(request.hash_algorithm)
    return request


def process_ocsp_request(
    data: bytes,
    db_path: str,
    ca_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    cache_ttl: int = 60,
    logger=None,
    client_ip: str = "-",
) -> tuple[int, bytes, str, OCSPDecision | None]:
    start = time.perf_counter()
    try:
        request = parse_ocsp_request(data)
        body, decision = build_ocsp_response(request, db_path, ca_cert, responder_cert, responder_key, cache_ttl)
        elapsed = int((time.perf_counter() - start) * 1000)
        if logger:
            logger.info(
                f'{{"event":"ocsp_request","client_ip":"{client_ip}","serial":"{decision.serial_hex}",'
                f'"status":"{decision.status}","issuer_matched":{str(decision.issuer_matched).lower()},'
                f'"processing_ms":{elapsed}}}'
            )
        return 200, body, "application/ocsp-response", decision
    except ValueError as exc:
        elapsed = int((time.perf_counter() - start) * 1000)
        if logger:
            logger.error(f'{{"event":"ocsp_error","client_ip":"{client_ip}","error":"{exc}","processing_ms":{elapsed}}}')
        return 400, build_unsuccessful_response(crypto_ocsp.OCSPResponseStatus.MALFORMED_REQUEST), "application/ocsp-response", None
    except Exception as exc:
        elapsed = int((time.perf_counter() - start) * 1000)
        if logger:
            logger.error(f'{{"event":"ocsp_error","client_ip":"{client_ip}","error":"{exc}","processing_ms":{elapsed}}}')
        return 500, build_unsuccessful_response(crypto_ocsp.OCSPResponseStatus.INTERNAL_ERROR), "application/ocsp-response", None
