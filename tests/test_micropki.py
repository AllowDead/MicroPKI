import argparse
import os
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID

from micropki.ca import confirm_overwrite, init_ca, verify_ca_certificate
from micropki.certificates import build_ca_certificate, generate_key
from micropki.cli import load_passphrase, validate_args
from micropki.crypto_utils import parse_dn
from micropki.logger import setup_logger


# TEST-5: Unit tests for core functions

def test_parse_dn_slash_format():
    dn = parse_dn("/CN=Test CA,O=Test Org,C=US")
    assert dn.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"
    assert dn.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "Test Org"


def test_parse_dn_comma_format():
    dn = parse_dn("CN=Comma CA, O=Comma Org")
    assert dn.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Comma CA"


def test_generate_rsa_key_size():
    key = generate_key("rsa", 4096)
    assert key.key_size == 4096


def test_generate_ecc_key():
    key = generate_key("ecc", 384)
    assert key.curve.name == "secp384r1"


def test_ca_extensions_include_critical_aki_matching_ski():
    key = generate_key("rsa", 4096)
    dn = parse_dn("CN=Test CA")
    cert = build_ca_certificate(dn, key, 365)

    basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)

    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is True
    assert key_usage.critical is True
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.crl_sign is True
    assert aki.critical is True
    assert aki.value.key_identifier == ski.value.digest


# TEST-4: Negative scenarios

def test_validate_missing_subject():
    logger = setup_logger()
    args = argparse.Namespace(
        subject="",
        key_type="rsa",
        key_size=4096,
        passphrase_file="/nonexistent",
        out_dir="./pki",
        validity_days="3650",
    )
    with pytest.raises(SystemExit):
        validate_args(args, logger)


def test_validate_bad_key_size():
    logger = setup_logger()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"testpass")
        pass_file = f.name
    try:
        args = argparse.Namespace(
            subject="/CN=Test",
            key_type="ecc",
            key_size=256,
            passphrase_file=pass_file,
            out_dir="./pki",
            validity_days="3650",
        )
        with pytest.raises(SystemExit):
            validate_args(args, logger)
    finally:
        os.unlink(pass_file)


def test_validate_nonexistent_passfile():
    logger = setup_logger()
    args = argparse.Namespace(
        subject="/CN=Test",
        key_type="rsa",
        key_size=4096,
        passphrase_file="/nonexistent/file.pass",
        out_dir="./pki",
        validity_days="3650",
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
            subject="INVALID_NO_EQUALS",
            key_type="rsa",
            key_size=4096,
            passphrase_file=pass_file,
            out_dir="./pki",
            validity_days="3650",
        )
        with pytest.raises(SystemExit):
            validate_args(args, logger)
    finally:
        os.unlink(pass_file)


def test_validate_negative_days():
    logger = setup_logger()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"testpass")
        pass_file = f.name
    try:
        args = argparse.Namespace(
            subject="/CN=Test",
            key_type="rsa",
            key_size=4096,
            passphrase_file=pass_file,
            out_dir="./pki",
            validity_days="-10",
        )
        with pytest.raises(SystemExit):
            validate_args(args, logger)
    finally:
        os.unlink(pass_file)


def test_validate_unwritable_out_dir():
    if os.name == "nt":
        pytest.skip("POSIX permission-bit test is not meaningful on Windows")

    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = os.path.join(tmpdir, "pass.txt")
        out_dir = os.path.join(tmpdir, "locked")
        with open(pass_file, "wb") as f:
            f.write(b"testpass")
        os.mkdir(out_dir)
        os.chmod(out_dir, 0o500)
        try:
            args = argparse.Namespace(
                subject="/CN=Test",
                key_type="rsa",
                key_size=4096,
                passphrase_file=pass_file,
                out_dir=out_dir,
                validity_days="3650",
            )
            with pytest.raises(SystemExit):
                validate_args(args, logger)
        finally:
            os.chmod(out_dir, 0o700)


# CLI-6: overwrite confirmation helper

def test_confirm_overwrite_accepts_yes():
    assert confirm_overwrite(["/tmp/ca.key.pem"], input_func=lambda _: "yes") is True


def test_confirm_overwrite_rejects_default_no():
    assert confirm_overwrite(["/tmp/ca.key.pem"], input_func=lambda _: "") is False


# TEST-1: self-consistency verification command backend

def test_verify_self_signed_certificate_success():
    logger = setup_logger()
    key = generate_key("rsa", 4096)
    dn = parse_dn("CN=Verify CA")
    cert = build_ca_certificate(dn, key, 365)

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = os.path.join(tmpdir, "ca.cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        assert verify_ca_certificate(cert_path, logger) is True


# TEST-2 and TEST-3: key/cert matching and encrypted key loading

def test_key_cert_match_and_decryption():
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = os.path.join(tmpdir, "pass.txt")
        with open(pass_file, "wb") as f:
            f.write(b"mysecret\n")

        passphrase = load_passphrase(pass_file)
        key = generate_key("rsa", 4096)
        dn = parse_dn("CN=Test CA")
        cert = build_ca_certificate(dn, key, 365)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )

        loaded_key = serialization.load_pem_private_key(key_pem, password=passphrase)
        assert loaded_key.key_size == 4096

        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        pub_key = cert_obj.public_key()

        data = b"test data for signature"
        signature = loaded_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())


def test_init_ca_overwrite_prompt_accepts(monkeypatch):
    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        pass_file = os.path.join(tmpdir, "pass.txt")
        out_dir = os.path.join(tmpdir, "pki")
        os.makedirs(os.path.join(out_dir, "private"))
        os.makedirs(os.path.join(out_dir, "certs"))
        with open(pass_file, "wb") as f:
            f.write(b"passphrase")
        with open(os.path.join(out_dir, "private", "ca.key.pem"), "wb") as f:
            f.write(b"old")

        monkeypatch.setattr("micropki.ca.confirm_overwrite", lambda paths: True)
        args = argparse.Namespace(
            subject="/CN=Prompt Test",
            key_type="ecc",
            key_size=384,
            passphrase_file=pass_file,
            passphrase_bytes=b"passphrase",
            out_dir=out_dir,
            validity_days=30,
            force=False,
        )
        init_ca(args, logger)
        assert os.path.exists(os.path.join(out_dir, "certs", "ca.cert.pem"))
