"""Simple Certificate Transparency simulation for MicroPKI."""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def default_ct_log_path(pki_root: str = "./pki") -> str:
    return os.path.join(os.path.abspath(pki_root), "audit", "ct.log")


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def certificate_fingerprint_sha256(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def append_ct_entry(cert: x509.Certificate, ct_log: str | None = None, pki_root: str = "./pki") -> str:
    from .crypto_utils import name_to_string
    ct_log = os.path.abspath(ct_log or default_ct_log_path(pki_root))
    os.makedirs(os.path.dirname(ct_log), exist_ok=True)
    serial_hex = f"{cert.serial_number:X}"
    line = " | ".join([
        _iso_now(),
        serial_hex,
        name_to_string(cert.subject),
        certificate_fingerprint_sha256(cert),
        name_to_string(cert.issuer),
    ])
    with open(ct_log, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if os.name != "nt":
        os.chmod(ct_log, 0o644)
    return ct_log


def certificate_in_ct_log(cert_path: str, ct_log: str | None = None, pki_root: str = "./pki") -> bool:
    from .certificates import load_certificate
    cert = load_certificate(cert_path)
    serial = f"{cert.serial_number:X}"
    fingerprint = certificate_fingerprint_sha256(cert)
    path = os.path.abspath(ct_log or default_ct_log_path(pki_root))
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if serial in line and fingerprint in line:
                return True
    return False
