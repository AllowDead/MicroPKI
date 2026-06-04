"""CRL generation for MicroPKI."""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

from .certificates import load_certificate, load_private_key
from .crypto_utils import name_to_string
from .database import (
    cert_time_to_iso,
    get_revoked_certificates_by_issuer,
    next_crl_number,
    upsert_crl_metadata,
    utc_now_iso,
)
from .revocation import reason_to_flag


@dataclass(frozen=True)
class CRLGenerationResult:
    ca_subject: str
    crl_number: int
    revoked_count: int
    this_update: str
    next_update: str
    path: str
    pem: bytes


def _signing_hash_for_key(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384() if isinstance(private_key.curve, ec.SECP384R1) else hashes.SHA256()
    raise ValueError("Unsupported CA private key type")


def _parse_iso_datetime(value: str) -> _dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = _dt.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _authority_key_identifier_for_crl(ca_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        return ca_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:
        try:
            ski = ca_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except x509.ExtensionNotFound:
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())


def build_crl(
    ca_cert: x509.Certificate,
    ca_private_key,
    revoked_records: list[dict],
    crl_number: int,
    next_update_days: int = 7,
) -> tuple[x509.CertificateRevocationList, _dt.datetime, _dt.datetime]:
    if next_update_days <= 0:
        raise ValueError("--next-update must be a positive integer number of days")
    this_update = _dt.datetime.now(_dt.timezone.utc)
    next_update = this_update + _dt.timedelta(days=int(next_update_days))
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(_authority_key_identifier_for_crl(ca_cert), critical=False)
        .add_extension(x509.CRLNumber(int(crl_number)), critical=False)
    )

    for record in revoked_records:
        revoked_at = _parse_iso_datetime(record["revocation_date"]) if record.get("revocation_date") else this_update
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(record["serial_hex"], 16))
            .revocation_date(revoked_at)
        )
        if record.get("revocation_reason"):
            revoked = revoked.add_extension(
                x509.CRLReason(reason_to_flag(record["revocation_reason"])),
                critical=False,
            )
        builder = builder.add_revoked_certificate(revoked.build())
    return builder.sign(private_key=ca_private_key, algorithm=_signing_hash_for_key(ca_private_key)), this_update, next_update


def serialize_crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)


def load_crl(path: str) -> x509.CertificateRevocationList:
    with open(path, "rb") as f:
        return x509.load_pem_x509_crl(f.read())


def default_ca_paths(out_dir: str, ca: str) -> tuple[str, str, str]:
    ca_normalized = ca.lower().strip()
    if ca_normalized == "root":
        return (
            os.path.join(out_dir, "certs", "ca.cert.pem"),
            os.path.join(out_dir, "private", "ca.key.pem"),
            "root",
        )
    if ca_normalized == "intermediate":
        return (
            os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            os.path.join(out_dir, "private", "intermediate.key.pem"),
            "intermediate",
        )
    return (ca, "", os.path.splitext(os.path.basename(ca))[0] or "ca")


def generate_crl(
    db_path: str,
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: bytes | None,
    out_file: str,
    next_update_days: int = 7,
    logger=None,
) -> CRLGenerationResult:
    if logger:
        logger.info(f"CRL generation started: ca_cert={os.path.abspath(ca_cert_path)}")
    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_private_key(ca_key_path, ca_passphrase)
    ca_subject = name_to_string(ca_cert.subject)
    revoked = get_revoked_certificates_by_issuer(db_path, ca_subject)
    crl_number = next_crl_number(db_path, ca_subject)
    crl, this_update, next_update = build_crl(ca_cert, ca_key, revoked, crl_number, next_update_days)
    pem = serialize_crl_to_pem(crl)
    os.makedirs(os.path.dirname(os.path.abspath(out_file)) or ".", exist_ok=True)
    with open(out_file, "wb") as f:
        f.write(pem)
    upsert_crl_metadata(
        db_path,
        ca_subject,
        crl_number,
        cert_time_to_iso(this_update),
        cert_time_to_iso(next_update),
        os.path.abspath(out_file),
    )
    if logger:
        logger.info(
            "CRL generation completed: "
            f"ca={ca_subject}, revoked={len(revoked)}, thisUpdate={cert_time_to_iso(this_update)}, "
            f"nextUpdate={cert_time_to_iso(next_update)}, crl_number={crl_number}, path={os.path.abspath(out_file)}"
        )
    return CRLGenerationResult(
        ca_subject=ca_subject,
        crl_number=crl_number,
        revoked_count=len(revoked),
        this_update=cert_time_to_iso(this_update),
        next_update=cert_time_to_iso(next_update),
        path=os.path.abspath(out_file),
        pem=pem,
    )


def crl_contains_serial(crl: x509.CertificateRevocationList, serial_hex: str) -> bool:
    wanted = int(serial_hex, 16)
    return any(entry.serial_number == wanted for entry in crl)
