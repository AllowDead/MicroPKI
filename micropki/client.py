"""Client-side operations: CSR generation, request-cert, validation and revocation status checks."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .certificates import generate_end_entity_key, load_certificate
from .crypto_utils import parse_dn
from .revocation_check import check_status_with_fallback
from .templates import parse_san_entries
from .validation import load_certificates_from_pem, validate_path


def _write_private_key(path: str, key) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if os.name != "nt":
        fd = os.open(path, flags, 0o600)
    else:
        fd = os.open(path, flags)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)


def generate_csr(subject: str, key_type: str, key_size: int, san_entries: list[str], out_key: str, out_csr: str, logger=None) -> tuple[str, str]:
    key = generate_end_entity_key(key_type, key_size)
    name = parse_dn(subject)
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    san_names = parse_san_entries(san_entries or [])
    if san_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    _write_private_key(out_key, key)
    os.makedirs(os.path.dirname(os.path.abspath(out_csr)) or ".", exist_ok=True)
    with open(out_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    if logger:
        logger.warning(f"Client private key is stored unencrypted: {os.path.abspath(out_key)}")
        logger.info(f"CSR generated: subject={subject}, csr={os.path.abspath(out_csr)}")
    return out_key, out_csr


def request_certificate(csr_path: str, template: str, ca_url: str, out_cert: str, api_key: str | None = None, logger=None) -> str:
    with open(csr_path, "rb") as f:
        data = f.read()
    url = ca_url.rstrip("/") + "/request-cert?" + urllib.parse.urlencode({"template": template})
    headers = {"Content-Type": "application/x-pem-file", "Accept": "application/x-pem-file"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f"Repository returned HTTP {resp.status}")
            cert_pem = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Certificate request failed: HTTP {exc.code}: {detail}") from exc
    os.makedirs(os.path.dirname(os.path.abspath(out_cert)) or ".", exist_ok=True)
    with open(out_cert, "wb") as f:
        f.write(cert_pem)
    if logger:
        logger.info(f"Certificate request completed: csr={os.path.abspath(csr_path)}, out_cert={os.path.abspath(out_cert)}")
    return out_cert


def validate_certificate_chain(cert_path: str, untrusted_paths: list[str], trusted_path: str, purpose: str | None = None, validation_time=None):
    leaf = load_certificate(cert_path)
    intermediates = []
    for path in untrusted_paths or []:
        intermediates.extend(load_certificates_from_pem(path))
    roots = load_certificates_from_pem(trusted_path)
    return validate_path(leaf, intermediates, roots, purpose=purpose, validation_time=validation_time)


def check_certificate_status(cert_path: str, ca_cert_path: str, crl: str | None = None, ocsp_url: str | None = None, logger=None):
    cert = load_certificate(cert_path)
    issuer = load_certificate(ca_cert_path)
    return check_status_with_fallback(cert, issuer, crl=crl, ocsp_url=ocsp_url, logger=logger)


def format_validation_result(result, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2)
    return result.to_text()
