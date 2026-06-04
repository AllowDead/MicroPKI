"""Certificate revocation workflow for MicroPKI."""

from __future__ import annotations

import sys
from typing import Callable, Optional

from cryptography import x509

from .database import get_certificate_by_serial, normalize_serial_hex, revoke_certificate

REASON_FLAGS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keycompromise": x509.ReasonFlags.key_compromise,
    "cacompromise": x509.ReasonFlags.ca_compromise,
    "affiliationchanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
    "certificatehold": x509.ReasonFlags.certificate_hold,
    "removefromcrl": x509.ReasonFlags.remove_from_crl,
    "privilegewithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aacompromise": x509.ReasonFlags.aa_compromise,
}

CANONICAL_REASONS = {
    "unspecified": "unspecified",
    "keycompromise": "keyCompromise",
    "cacompromise": "cACompromise",
    "affiliationchanged": "affiliationChanged",
    "superseded": "superseded",
    "cessationofoperation": "cessationOfOperation",
    "certificatehold": "certificateHold",
    "removefromcrl": "removeFromCRL",
    "privilegewithdrawn": "privilegeWithdrawn",
    "aacompromise": "aACompromise",
}


def normalize_reason(reason: Optional[str]) -> str:
    key = (reason or "unspecified").replace("_", "").replace("-", "").strip().lower()
    if key not in CANONICAL_REASONS:
        supported = ", ".join(CANONICAL_REASONS.values())
        raise ValueError(f"Unsupported revocation reason: {reason}. Supported reasons: {supported}")
    return CANONICAL_REASONS[key]


def reason_to_flag(reason: Optional[str]) -> x509.ReasonFlags:
    canonical = normalize_reason(reason)
    key = canonical.replace("_", "").replace("-", "").lower()
    return REASON_FLAGS[key]


def confirm_revocation(serial: str, reason: str, input_func: Callable[[str], str] = input) -> bool:
    try:
        answer = input_func(f"Revoke certificate {serial} with reason {reason}? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes", "д", "да"}


def revoke_by_serial(db_path: str, serial: str, reason: str = "unspecified", force: bool = False, logger=None) -> dict | None:
    serial_hex = normalize_serial_hex(serial)
    canonical_reason = normalize_reason(reason)
    record = get_certificate_by_serial(db_path, serial_hex)
    if not record:
        msg = f"Certificate not found: serial={serial_hex}"
        if logger:
            logger.error(msg)
        raise KeyError(msg)
    if record["status"] == "revoked":
        if logger:
            logger.warning(f"Certificate already revoked: serial={serial_hex}")
        return record
    if not force and not confirm_revocation(serial_hex, canonical_reason):
        raise PermissionError("Revocation cancelled by user")
    status, updated = revoke_certificate(db_path, serial_hex, canonical_reason)
    if status == "not_found":
        msg = f"Certificate not found: serial={serial_hex}"
        if logger:
            logger.error(msg)
        raise KeyError(msg)
    if status == "already_revoked":
        if logger:
            logger.warning(f"Certificate already revoked: serial={serial_hex}")
        return updated
    if logger:
        logger.info(f"Certificate revoked: serial={serial_hex}, reason={canonical_reason}, timestamp={updated['revocation_date']}")
    return updated
