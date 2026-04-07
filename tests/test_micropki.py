import os
import tempfile
import pytest
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from micropki.crypto_utils import parse_dn
from micropki.certificates import generate_key, build_ca_certificate
from micropki.cli import validate_args, load_passphrase
from micropki.logger import setup_logger
import argparse


# TEST-5: Модульные тесты
def test_parse_dn_slash_format():
    dn = parse_dn("/CN=Test CA,O=Test Org,C=US")
    assert dn.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"
    assert dn.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "Test Org"


def test_parse_dn_comma_format():
    dn = parse_dn("CN=Comma CA, O=Comma Org")
    assert dn.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Comma CA"


def test_generate_rsa_key_size():
    key = generate_key('rsa', 4096)
    assert key.key_size == 4096


def test_generate_ecc_key():
    key = generate_key('ecc', 384)
    assert key.curve.name == "secp384r1"


# TEST-4: Негативные сценарии
def test_validate_missing_subject():
    logger = setup_logger()
    args = argparse.Namespace(
        subject="", key_type="rsa", key_size=4096,
        passphrase_file="/nonexistent", out_dir="./pki", validity_days="3650"
    )
    with pytest.raises(SystemExit):
        validate_args(args, logger)


def test_validate_bad_key_size():
    logger = setup_logger()
    # Создаем временный файл пароля, чтобы пройти первую проверку
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"testpass")
        pass_file = f.name
    try:
        args = argparse.Namespace(
            subject="/CN=Test", key_type="ecc", key_size=256,
            passphrase_file=pass_file, out_dir="./pki", validity_days="3650"
        )
        with pytest.raises(SystemExit):
            validate_args(args, logger)
    finally:
        os.unlink(pass_file)


# Интеграционный тест (TEST-2, TEST-3)
def test_key_cert_match_and_decryption():
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = os.path.join(tmpdir, "pass.txt")
        with open(pass_file, "wb") as f:
            f.write(b"mysecret\n")

        passphrase = load_passphrase(pass_file)

        # Генерация и сериализация
        key = generate_key('rsa', 4096)
        dn = parse_dn("CN=Test CA")
        cert = build_ca_certificate(dn, key, 365)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        )

        # TEST-3: Попытка расшифровать ключ (демонстрация)
        loaded_key = serialization.load_pem_private_key(key_pem, password=passphrase)
        assert loaded_key.key_size == 4096

        # TEST-2: Проверка соответствия ключа и сертификата
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        pub_key = cert_obj.public_key()

        # Создаем тестовую подпись закрытым ключом
        data = b"test data for signature"
        signature = loaded_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        # Проверяем открытым ключом из сертификата
        pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        assert True  # Если не выбросило исключение, тест пройден

def test_validate_nonexistent_passfile():
    logger = setup_logger()
    args = argparse.Namespace(
        subject="/CN=Test", key_type="rsa", key_size=4096,
        passphrase_file="/nonexistent/file.pass", out_dir="./pki", validity_days="3650"
    )
    with pytest.raises(SystemExit):
        validate_args(args, logger)

def test_validate_bad_dn_syntax():
    logger = setup_logger()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"testpass")
        pass_file = f.name
    try:
        args = argparse.Namespace(
            subject="INVALID_NO_EQUALS", key_type="rsa", key_size=4096,
            passphrase_file=pass_file, out_dir="./pki", validity_days="3650"
        )
        with pytest.raises(ValueError):
            from micropki.crypto_utils import parse_dn
            parse_dn(args.subject)
    finally:
        os.unlink(pass_file)

def test_validate_negative_days():
    logger = setup_logger()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"testpass")
        pass_file = f.name
    try:
        args = argparse.Namespace(
            subject="/CN=Test", key_type="rsa", key_size=4096,
            passphrase_file=pass_file, out_dir="./pki", validity_days="-10"
        )
        with pytest.raises(SystemExit):
            validate_args(args, logger)
    finally:
        os.unlink(pass_file)