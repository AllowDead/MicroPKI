import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtendedKeyUsageOID


def generate_key(key_type, key_size):
    if key_type == 'rsa':
        if key_size != 4096:
            raise ValueError("Для RSA обязателен размер ключа 4096")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == 'ecc':
        if key_size != 384:
            raise ValueError("Для ECC обязателен размер ключа 384 (NIST P-384)")
        return ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def build_ca_certificate(subject_name, private_key, validity_days):
    public_key = private_key.public_key()
    subject = subject_name
    issuer = subject_name

    utc_now = datetime.datetime.now(datetime.timezone.utc)

    # Серийный номер
    rand_bytes = bytearray(os.urandom(20))
    rand_bytes[0] &= 0x7F  # Обнуляем старший бит
    serial_number = int.from_bytes(rand_bytes, byteorder='big')

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(utc_now)
    builder = builder.not_valid_after(utc_now + datetime.timedelta(days=validity_days))

    # PKI-3: Расширения
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False
    )

    # Выбор алгоритма подписи
    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    else:
        algorithm = hashes.SHA384()  # ecdsa-with-SHA384 для ECC P-384

    certificate = builder.sign(private_key, algorithm)
    return certificate


def serialize_cert_to_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)