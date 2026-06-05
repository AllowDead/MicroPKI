"""Private-key compromise simulation support."""

from __future__ import annotations

import os
from cryptography.hazmat.primitives import serialization

from .certificates import load_certificate
from .database import mark_key_compromised
from .policy import public_key_hash
from .revocation import normalize_reason, revoke_by_serial


def compromise_certificate(
    db_path: str,
    cert_path: str,
    reason: str = "keyCompromise",
    force: bool = False,
    logger=None,
) -> dict:
    cert = load_certificate(cert_path)
    serial_hex = f"{cert.serial_number:X}"
    canonical_reason = normalize_reason(reason or "keyCompromise")
    updated = revoke_by_serial(db_path, serial_hex, canonical_reason, force=force, logger=logger)
    key_hash = public_key_hash(cert.public_key())
    mark_key_compromised(db_path, key_hash, serial_hex, canonical_reason)
    if logger:
        logger.error(f"Private key compromise simulated: serial={serial_hex}, public_key_hash={key_hash}")
    return {"serial_hex": serial_hex, "public_key_hash": key_hash, "record": updated}
