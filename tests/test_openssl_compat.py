import os
import subprocess
import tempfile
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID

from micropki.certificates import generate_key, build_ca_certificate
from micropki.crypto_utils import parse_dn


def test_openssl_structural_compatibility():

    subject_str = "CN=Demo Root CA"
    dn = parse_dn(subject_str)

    # 1. Генерируем сертификат нашим кодом (MicroPKI)
    mpki_key = generate_key('rsa', 4096)
    mpki_cert = build_ca_certificate(dn, mpki_key, 7300)

    # 2. Генерируем сертификат через OpenSSL CLI
    # Создаем временный конфиг для OpenSSL
    openssl_config = """
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = Demo Root CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "openssl.cnf")
        key_path = os.path.join(tmpdir, "test.key")
        cert_path = os.path.join(tmpdir, "test.crt")

        with open(config_path, "w") as f:
            f.write(openssl_config)

        # Генерация ключа и сертификата OpenSSL
        subprocess.run([
            "openssl", "req", "-x509", "-new", "-nodes",
            "-newkey", "rsa:4096",
            "-keyout", key_path,
            "-out", cert_path,
            "-days", "7300",
            "-config", config_path
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Читаем сертификат OpenSSL
        with open(cert_path, "rb") as f:
            openssl_cert = x509.load_pem_x509_certificate(f.read())

    # 3. Сравниваем СТРУКТУРУ (не байты!)

    # Версия (обе должны быть v3)
    assert mpki_cert.version == openssl_cert.version == x509.Version.v3

    # Субъект
    assert mpki_cert.subject == openssl_cert.subject

    # Издатель (для самоподписанных равен субъекту)
    assert mpki_cert.issuer == openssl_cert.issuer

    # Алгоритм подписи
    assert mpki_cert.signature_algorithm_oid == openssl_cert.signature_algorithm_oid
    assert mpki_cert.signature_hash_algorithm.name == openssl_cert.signature_hash_algorithm.name == "sha256"

    # Расширения: Basic Constraints
    mpki_bc = mpki_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    openssl_bc = openssl_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert mpki_bc.ca == openssl_bc.ca == True
    assert mpki_bc.path_length is None
    assert mpki_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).critical == True

    # Расширения: Key Usage
    mpki_ku = mpki_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    openssl_ku = openssl_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    assert mpki_ku.key_cert_sign == openssl_ku.key_cert_sign == True
    assert mpki_ku.crl_sign == openssl_ku.crl_sign == True
    assert mpki_ku.digital_signature == openssl_ku.digital_signature == True
    assert mpki_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).critical == True

    # Расширения: SKI и AKI (просто проверяем их наличие)
    mpki_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    mpki_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)

