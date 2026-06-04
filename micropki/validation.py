"""Client-side certificate path validation for MicroPKI."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


@dataclass
class CertStep:
    subject: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    ok: bool
    chain_subjects: list[str]
    steps: list[CertStep]
    error: Optional[str] = None

    def to_text(self) -> str:
        lines = ["PASS" if self.ok else "FAIL"]
        if self.chain_subjects:
            lines.append("Chain:")
            for item in self.chain_subjects:
                lines.append(f"  - {item}")
        for step in self.steps:
            lines.append(f"Certificate: {step.subject}")
            for passed in step.passed:
                lines.append(f"  OK: {passed}")
            for failed in step.failed:
                lines.append(f"  FAIL: {failed}")
        if self.error:
            lines.append(f"Error: {self.error}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "chain": self.chain_subjects,
            "steps": [{"subject": s.subject, "passed": s.passed, "failed": s.failed} for s in self.steps],
            "error": self.error,
        }


def load_certificates_from_pem(path: str) -> list[x509.Certificate]:
    with open(path, "rb") as f:
        data = f.read()
    certs: list[x509.Certificate] = []
    marker = b"-----BEGIN CERTIFICATE-----"
    for chunk in data.split(marker):
        if not chunk.strip():
            continue
        pem = marker + chunk
        certs.append(x509.load_pem_x509_certificate(pem))
    return certs


def _name(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    else:
        raise ValueError("Unsupported issuer public key type")


def build_chain(leaf: x509.Certificate, intermediates: Iterable[x509.Certificate], roots: Iterable[x509.Certificate]) -> list[x509.Certificate]:
    """Return [leaf, intermediate..., trusted_root] or raise ValueError."""
    roots = list(roots)
    inters = list(intermediates)

    def is_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
        if child.issuer != issuer.subject:
            return False
        try:
            _verify_signature(child, issuer)
            return True
        except Exception:
            return False

    queue: list[tuple[x509.Certificate, list[x509.Certificate], list[x509.Certificate]]] = [(leaf, [leaf], inters)]
    while queue:
        current, path, remaining = queue.pop(0)
        for root in roots:
            if is_signed_by(current, root):
                return path + [root]
        for idx, candidate in enumerate(remaining):
            if is_signed_by(current, candidate):
                rest = remaining[:idx] + remaining[idx + 1 :]
                queue.append((candidate, path + [candidate], rest))
    raise ValueError("Could not build a chain to a trusted root")


def _reference_time(validation_time: _dt.datetime | None) -> _dt.datetime:
    if validation_time is None:
        return _dt.datetime.now(_dt.timezone.utc)
    if validation_time.tzinfo is None:
        return validation_time.replace(tzinfo=_dt.timezone.utc)
    return validation_time.astimezone(_dt.timezone.utc)


def _check_validity(cert: x509.Certificate, when: _dt.datetime) -> None:
    if when < cert.not_valid_before_utc:
        raise ValueError("certificate is not yet valid")
    if when > cert.not_valid_after_utc:
        raise ValueError("certificate is expired")


def _basic_constraints(cert: x509.Certificate) -> x509.BasicConstraints:
    return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value


def _key_usage(cert: x509.Certificate) -> x509.KeyUsage | None:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return None


def _check_purpose(cert: x509.Certificate, purpose: str | None) -> None:
    if not purpose:
        return
    expected = {
        "server": ExtendedKeyUsageOID.SERVER_AUTH,
        "client": ExtendedKeyUsageOID.CLIENT_AUTH,
        "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        "ocsp": ExtendedKeyUsageOID.OCSP_SIGNING,
    }.get(purpose)
    if expected is None:
        return
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if expected not in eku:
        raise ValueError(f"certificate EKU does not allow {purpose}")


def validate_path(
    leaf: x509.Certificate,
    intermediates: Iterable[x509.Certificate],
    roots: Iterable[x509.Certificate],
    purpose: str | None = None,
    validation_time: _dt.datetime | None = None,
) -> ValidationResult:
    steps: list[CertStep] = []
    try:
        chain = build_chain(leaf, intermediates, roots)
    except Exception as exc:
        return ValidationResult(False, [], [], str(exc))

    when = _reference_time(validation_time)
    chain_subjects = [_name(c) for c in chain]
    try:
        for index, cert in enumerate(chain):
            step = CertStep(_name(cert))
            steps.append(step)
            is_leaf = index == 0
            is_root = index == len(chain) - 1
            issuer = cert if is_root else chain[index + 1]

            _verify_signature(cert, issuer)
            step.passed.append("signature")
            _check_validity(cert, when)
            step.passed.append("validity period")

            bc = _basic_constraints(cert)
            if is_leaf:
                if bc.ca:
                    raise ValueError("leaf certificate has CA=TRUE")
                step.passed.append("leaf BasicConstraints CA=FALSE")
                ku = _key_usage(cert)
                if ku is not None and purpose in {"server", "client", "code_signing"} and not ku.digital_signature:
                    raise ValueError("leaf key usage does not allow digitalSignature")
                _check_purpose(cert, purpose)
                step.passed.append("leaf key usage / EKU")
            else:
                if not bc.ca:
                    raise ValueError("issuer certificate has CA=FALSE")
                step.passed.append("issuer BasicConstraints CA=TRUE")
                ku = _key_usage(cert)
                if ku is not None and not ku.key_cert_sign:
                    raise ValueError("issuer key usage does not allow keyCertSign")
                step.passed.append("issuer key usage keyCertSign")
                if not is_root and bc.path_length is not None:
                    subordinate_ca_count = sum(1 for c in chain[:index] if _basic_constraints(c).ca)
                    if subordinate_ca_count > bc.path_length:
                        raise ValueError("pathLenConstraint exceeded")
                    step.passed.append("path length constraint")
        return ValidationResult(True, chain_subjects, steps)
    except Exception as exc:
        if steps:
            steps[-1].failed.append(str(exc))
        return ValidationResult(False, chain_subjects, steps, str(exc))
