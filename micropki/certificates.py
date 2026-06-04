import datetime
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


def generate_key(key_type, key_size):
    if key_type == "rsa":
        if key_size != 4096:
            raise ValueError("Для RSA обязателен размер ключа 4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ecc":
        if key_size != 384:
            raise ValueError("Для ECC обязателен размер ключа 384 (NIST P-384)")
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def generate_end_entity_key(key_type="rsa", key_size=2048):
    if key_type == "rsa":
        if key_size < 2048:
            raise ValueError("Для конечного RSA-сертификата нужен ключ не меньше 2048 бит")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ecc":
        if key_size >= 384:
            return ec.generate_private_key(ec.SECP384R1())
        if key_size >= 256:
            return ec.generate_private_key(ec.SECP256R1())
        raise ValueError("Для конечного ECC-сертификата нужен ключ не меньше P-256")
    raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def _random_positive_serial_number():
    while True:
        rand_bytes = bytearray(os.urandom(20))
        rand_bytes[0] &= 0x7F
        serial_number = int.from_bytes(rand_bytes, byteorder="big")
        if serial_number > 0:
            return serial_number


def _signing_hash_for_key(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384() if isinstance(private_key.curve, ec.SECP384R1) else hashes.SHA256()
    raise ValueError("Неподдерживаемый тип приватного ключа")


def _authority_key_identifier_from_cert(issuer_cert):
    try:
        ski = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())


def build_ca_certificate(subject_name, private_key, validity_days, serial_number=None):
    public_key = private_key.public_key()
    subject = subject_name
    issuer = subject_name
    utc_now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number or _random_positive_serial_number())
    builder = builder.not_valid_before(utc_now)
    builder = builder.not_valid_after(utc_now + datetime.timedelta(days=validity_days))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
        critical=True,
    )

    return builder.sign(private_key, _signing_hash_for_key(private_key))


def build_intermediate_certificate(csr, root_cert, root_private_key, validity_days, pathlen=0, serial_number=None):
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    public_key = csr.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number or _random_positive_serial_number())
    builder = builder.not_valid_before(utc_now)
    builder = builder.not_valid_after(utc_now + datetime.timedelta(days=validity_days))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(_authority_key_identifier_from_cert(root_cert), critical=False)
    return builder.sign(root_private_key, _signing_hash_for_key(root_private_key))


def _key_usage_for_template(template, public_key):
    is_rsa = isinstance(public_key, rsa.RSAPublicKey)
    if template == "server":
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=is_rsa,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=False,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def build_end_entity_certificate(subject, public_key, issuer_cert, issuer_private_key, template, san_names, validity_days, serial_number=None):
    from .templates import eku_for_template

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number or _random_positive_serial_number())
    builder = builder.not_valid_before(utc_now)
    builder = builder.not_valid_after(utc_now + datetime.timedelta(days=validity_days))
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(_key_usage_for_template(template, public_key), critical=True)
    builder = builder.add_extension(eku_for_template(template), critical=False)
    if san_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(_authority_key_identifier_from_cert(issuer_cert), critical=False)
    return builder.sign(issuer_private_key, _signing_hash_for_key(issuer_private_key))



def build_ocsp_responder_certificate(subject, public_key, issuer_cert, issuer_private_key, san_names=None, validity_days=365, serial_number=None):
    """Build an OCSP responder signing certificate.

    Profile: CA=FALSE, KeyUsage=digitalSignature only, EKU=id-kp-OCSPSigning.
    """
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number or _random_positive_serial_number())
    builder = builder.not_valid_before(utc_now)
    builder = builder.not_valid_after(utc_now + datetime.timedelta(days=validity_days))
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
        critical=False,
    )
    if san_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(_authority_key_identifier_from_cert(issuer_cert), critical=False)
    return builder.sign(issuer_private_key, _signing_hash_for_key(issuer_private_key))


def serialize_cert_to_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def load_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(path, passphrase):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)
