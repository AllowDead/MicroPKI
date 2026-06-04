import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


def verify_signature(child_cert, issuer_cert):
    issuer_public_key = issuer_cert.public_key()
    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm,
        )
    elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            ec.ECDSA(child_cert.signature_hash_algorithm),
        )
    else:
        raise ValueError("Неподдерживаемый тип публичного ключа issuer")


def _check_time(cert, label):
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise ValueError(f"{label}: сертификат вне периода действия")


def _check_ca(cert, label):
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if not bc.ca:
        raise ValueError(f"{label}: BasicConstraints не содержит CA=TRUE")
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not ku.key_cert_sign or not ku.crl_sign:
        raise ValueError(f"{label}: KeyUsage не разрешает подпись сертификатов/CRL")
    return bc


def _check_leaf(cert, purpose=None):
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if bc.ca:
        raise ValueError("leaf: конечный сертификат не должен иметь CA=TRUE")
    if purpose:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        expected = {
            "server": ExtendedKeyUsageOID.SERVER_AUTH,
            "client": ExtendedKeyUsageOID.CLIENT_AUTH,
            "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        }[purpose]
        if expected not in eku:
            raise ValueError(f"leaf: EKU не соответствует purpose={purpose}")


def validate_chain(root_cert, intermediate_cert, leaf_cert, purpose=None):
    """Validate leaf -> intermediate -> root signatures, validity, BC and basic KU/EKU."""
    if root_cert.subject != root_cert.issuer:
        raise ValueError("root: Subject должен совпадать с Issuer")
    verify_signature(root_cert, root_cert)
    _check_time(root_cert, "root")
    _check_ca(root_cert, "root")

    if intermediate_cert.issuer != root_cert.subject:
        raise ValueError("intermediate: Issuer не совпадает с Root Subject")
    verify_signature(intermediate_cert, root_cert)
    _check_time(intermediate_cert, "intermediate")
    bc = _check_ca(intermediate_cert, "intermediate")
    if bc.path_length is not None and bc.path_length < 0:
        raise ValueError("intermediate: некорректный path length")

    if leaf_cert.issuer != intermediate_cert.subject:
        raise ValueError("leaf: Issuer не совпадает с Intermediate Subject")
    verify_signature(leaf_cert, intermediate_cert)
    _check_time(leaf_cert, "leaf")
    _check_leaf(leaf_cert, purpose)
    return True
