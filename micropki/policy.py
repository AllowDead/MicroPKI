"""Security policy enforcement for Sprint 7."""

from __future__ import annotations

import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

MAX_VALIDITY_DAYS = {
    "root": 3650,
    "intermediate": 1825,
    "end_entity": 365,
    "ocsp": 365,
}


def enforce_validity(role: str, validity_days: int) -> None:
    maximum = MAX_VALIDITY_DAYS[role]
    if int(validity_days) > maximum:
        raise ValueError(f"Policy violation: {role} validity must not exceed {maximum} days")
    if int(validity_days) <= 0:
        raise ValueError("Policy violation: validity must be positive")


def _ec_curve_bits(curve) -> int:
    if isinstance(curve, ec.SECP384R1):
        return 384
    if isinstance(curve, ec.SECP256R1):
        return 256
    return int(getattr(curve, "key_size", 0) or 0)


def enforce_public_key(public_key, role: str) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        size = public_key.key_size
        if role == "root" and size < 4096:
            raise ValueError("Policy violation: Root CA RSA key must be at least 4096 bits")
        if role == "intermediate" and size < 3072:
            raise ValueError("Policy violation: Intermediate CA RSA key must be at least 3072 bits")
        if role in {"end_entity", "ocsp"} and size < 2048:
            raise ValueError("Policy violation: end-entity RSA key must be at least 2048 bits")
        if size < 2048:
            raise ValueError("Policy violation: RSA key must be at least 2048 bits")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        bits = _ec_curve_bits(public_key.curve)
        if role in {"root", "intermediate"} and bits < 384:
            raise ValueError("Policy violation: CA ECC key must be at least P-384")
        if role in {"end_entity", "ocsp"} and bits < 256:
            raise ValueError("Policy violation: end-entity ECC key must be at least P-256")
        return
    raise ValueError("Policy violation: unsupported public key algorithm")


def enforce_private_key(private_key, role: str) -> None:
    enforce_public_key(private_key.public_key(), role)


def enforce_pathlen_for_intermediate(pathlen: int) -> None:
    if int(pathlen) != 0:
        raise ValueError("Policy violation: Intermediate CA pathLen must be 0")


def _hash_strength(hash_alg) -> int:
    if hash_alg is None:
        return 0
    if isinstance(hash_alg, hashes.SHA1):
        return 1
    if isinstance(hash_alg, hashes.SHA224):
        return 224
    if isinstance(hash_alg, hashes.SHA256):
        return 256
    if isinstance(hash_alg, hashes.SHA384):
        return 384
    if isinstance(hash_alg, hashes.SHA512):
        return 512
    return int(getattr(hash_alg, "digest_size", 0) * 8)


def enforce_csr_signature_algorithm(csr: x509.CertificateSigningRequest) -> None:
    public_key = csr.public_key()
    hash_alg = csr.signature_hash_algorithm
    strength = _hash_strength(hash_alg)
    if isinstance(public_key, rsa.RSAPublicKey):
        if strength < 256:
            raise ValueError("Policy violation: RSA CSR signature must use SHA-256 or stronger")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        bits = _ec_curve_bits(public_key.curve)
        if bits >= 384 and strength < 384:
            raise ValueError("Policy violation: P-384 CSR signature must use SHA-384 or stronger")
        if bits == 256 and strength < 256:
            raise ValueError("Policy violation: P-256 CSR signature must use SHA-256 or stronger")
    else:
        raise ValueError("Policy violation: unsupported CSR public key algorithm")


def enforce_csr(csr: x509.CertificateSigningRequest, role: str = "end_entity") -> None:
    enforce_public_key(csr.public_key(), role)
    enforce_csr_signature_algorithm(csr)


def enforce_no_wildcards(template: str, san_names, allow_wildcards: bool = False) -> None:
    if allow_wildcards or template != "server":
        return
    for name in san_names or []:
        if isinstance(name, x509.DNSName) and str(name.value).startswith("*."):
            raise ValueError("Policy violation: wildcard DNS SAN is rejected by default")


def enforce_template_policy(template: str, san_names, allow_wildcards: bool = False) -> None:
    from .templates import validate_template_sans
    validate_template_sans(template, san_names)
    enforce_no_wildcards(template, san_names, allow_wildcards=allow_wildcards)


def public_key_hash(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import hashlib
    return hashlib.sha256(der).hexdigest()
