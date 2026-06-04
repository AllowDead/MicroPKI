import argparse
import os
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from micropki.ca import issue_cert, issue_intermediate, verify_chain
from micropki.certificates import (
    build_end_entity_certificate,
    build_intermediate_certificate,
    generate_end_entity_key,
    generate_key,
)
from micropki.chain import validate_chain
from micropki.cli import validate_issue_cert_args
from micropki.crypto_utils import parse_dn
from micropki.csr import generate_intermediate_csr, verify_csr_signature
from micropki.logger import setup_logger
from micropki.templates import parse_san_entries, validate_template_sans


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _encrypted_key(key, password=b"pass"):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def _prepare_root_files(tmpdir):
    from micropki.certificates import build_ca_certificate
    root_key = generate_key("rsa", 4096)
    root_cert = build_ca_certificate(parse_dn("CN=Root CA,O=MicroPKI"), root_key, 3650)
    root_cert_path = os.path.join(tmpdir, "root.cert.pem")
    root_key_path = os.path.join(tmpdir, "root.key.pem")
    root_pass_path = os.path.join(tmpdir, "root.pass")
    _write(root_cert_path, _pem_cert(root_cert))
    _write(root_key_path, _encrypted_key(root_key, b"rootpass"))
    _write(root_pass_path, b"rootpass")
    return root_key, root_cert, root_cert_path, root_key_path, root_pass_path


def _prepare_intermediate_files(tmpdir):
    root_key, root_cert, _, _, _ = _prepare_root_files(tmpdir)
    inter_key = generate_key("rsa", 4096)
    csr = generate_intermediate_csr(parse_dn("CN=Intermediate CA,O=MicroPKI"), inter_key, pathlen=0)
    inter_cert = build_intermediate_certificate(csr, root_cert, root_key, 1825, pathlen=0)
    inter_cert_path = os.path.join(tmpdir, "intermediate.cert.pem")
    inter_key_path = os.path.join(tmpdir, "intermediate.key.pem")
    inter_pass_path = os.path.join(tmpdir, "inter.pass")
    _write(inter_cert_path, _pem_cert(inter_cert))
    _write(inter_key_path, _encrypted_key(inter_key, b"interpass"))
    _write(inter_pass_path, b"interpass")
    return root_cert, inter_cert, inter_key, inter_cert_path, inter_key_path, inter_pass_path


def test_parse_multiple_san_entries():
    sans = parse_san_entries(["dns:example.com", "dns:www.example.com", "ip:192.168.1.1", "email:a@example.com", "uri:https://example.com/app"])
    assert any(isinstance(x, x509.DNSName) and x.value == "example.com" for x in sans)
    assert any(isinstance(x, x509.IPAddress) for x in sans)
    assert any(isinstance(x, x509.RFC822Name) for x in sans)
    assert any(isinstance(x, x509.UniformResourceIdentifier) for x in sans)


def test_template_validation_rejects_server_without_san():
    with pytest.raises(ValueError):
        validate_template_sans("server", [])


def test_template_validation_rejects_code_signing_ip_san():
    sans = parse_san_entries(["ip:192.168.1.10"])
    with pytest.raises(ValueError):
        validate_template_sans("code_signing", sans)


def test_intermediate_csr_generation_contains_basic_constraints():
    key = generate_key("rsa", 4096)
    csr = generate_intermediate_csr(parse_dn("CN=Intermediate CA"), key, pathlen=0)
    verify_csr_signature(csr)
    bc = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0


def test_intermediate_certificate_extensions():
    root_key = generate_key("rsa", 4096)
    from micropki.certificates import build_ca_certificate
    root_cert = build_ca_certificate(parse_dn("CN=Root CA"), root_key, 3650)
    inter_key = generate_key("rsa", 4096)
    csr = generate_intermediate_csr(parse_dn("CN=Intermediate CA"), inter_key, pathlen=0)
    cert = build_intermediate_certificate(csr, root_cert, root_key, 1825, pathlen=0)

    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)

    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0
    assert ku.critical is True
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True
    assert ski.value.digest
    assert aki.value.key_identifier


def test_server_certificate_extensions_and_san():
    root_cert, inter_cert, inter_key, *_ = _prepare_intermediate_files(tempfile.mkdtemp())
    leaf_key = generate_end_entity_key("rsa", 2048)
    sans = parse_san_entries(["dns:example.com", "ip:192.168.1.10"])
    cert = build_end_entity_certificate(parse_dn("CN=example.com"), leaf_key.public_key(), inter_cert, inter_key, "server", sans, 365)
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert bc.critical is True
    assert bc.value.ca is False
    assert ku.critical is True
    assert ku.value.digital_signature is True
    assert ku.value.key_encipherment is True
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert "example.com" in san.get_values_for_type(x509.DNSName)


def test_chain_validation_success():
    root_key = generate_key("rsa", 4096)
    from micropki.certificates import build_ca_certificate
    root_cert = build_ca_certificate(parse_dn("CN=Root CA"), root_key, 3650)
    inter_key = generate_key("rsa", 4096)
    csr = generate_intermediate_csr(parse_dn("CN=Intermediate CA"), inter_key, pathlen=0)
    inter_cert = build_intermediate_certificate(csr, root_cert, root_key, 1825, pathlen=0)
    leaf_key = generate_end_entity_key("rsa", 2048)
    sans = parse_san_entries(["dns:example.com"])
    leaf_cert = build_end_entity_certificate(parse_dn("CN=example.com"), leaf_key.public_key(), inter_cert, inter_key, "server", sans, 365)
    assert validate_chain(root_cert, inter_cert, leaf_cert, purpose="server") is True


def test_issue_intermediate_writes_files_and_updates_policy():
    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        _, _, root_cert_path, root_key_path, root_pass_path = _prepare_root_files(tmpdir)
        inter_pass_path = os.path.join(tmpdir, "inter.pass")
        _write(inter_pass_path, b"interpass")
        out_dir = os.path.join(tmpdir, "pki")
        args = argparse.Namespace(
            root_cert=root_cert_path,
            root_key=root_key_path,
            root_pass_file=root_pass_path,
            root_passphrase_bytes=b"rootpass",
            subject="CN=Intermediate CA,O=MicroPKI",
            key_type="rsa",
            key_size=4096,
            passphrase_file=inter_pass_path,
            passphrase_bytes=b"interpass",
            out_dir=out_dir,
            validity_days=1825,
            pathlen=0,
        )
        issue_intermediate(args, logger)
        assert os.path.exists(os.path.join(out_dir, "private", "intermediate.key.pem"))
        assert os.path.exists(os.path.join(out_dir, "certs", "intermediate.cert.pem"))
        assert os.path.exists(os.path.join(out_dir, "csrs", "intermediate.csr.pem"))
        assert "Intermediate CA" in open(os.path.join(out_dir, "policy.txt"), encoding="utf-8").read()


def test_issue_cert_wrong_intermediate_passphrase_fails():
    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        _, _, _, inter_cert_path, inter_key_path, inter_pass_path = _prepare_intermediate_files(tmpdir)
        args = argparse.Namespace(
            ca_cert=inter_cert_path,
            ca_key=inter_key_path,
            ca_pass_file=inter_pass_path,
            ca_passphrase_bytes=b"wrongpass",
            template="server",
            subject="CN=example.com",
            san=["dns:example.com"],
            out_dir=tmpdir,
            validity_days=365,
            csr=None,
        )
        with pytest.raises(SystemExit):
            issue_cert(args, logger)


def test_issue_cert_csr_requesting_ca_true_is_rejected():
    from micropki.csr import serialize_csr_to_pem
    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        _, _, _, inter_cert_path, inter_key_path, inter_pass_path = _prepare_intermediate_files(tmpdir)
        bad_key = generate_key("rsa", 4096)
        bad_csr = generate_intermediate_csr(parse_dn("CN=bad.example"), bad_key, pathlen=0)
        csr_path = os.path.join(tmpdir, "bad.csr.pem")
        _write(csr_path, serialize_csr_to_pem(bad_csr))
        args = argparse.Namespace(
            ca_cert=inter_cert_path,
            ca_key=inter_key_path,
            ca_pass_file=inter_pass_path,
            ca_passphrase_bytes=b"interpass",
            template="server",
            subject="CN=bad.example",
            san=["dns:bad.example"],
            out_dir=tmpdir,
            validity_days=365,
            csr=csr_path,
        )
        with pytest.raises(SystemExit):
            issue_cert(args, logger)


def test_validate_issue_cert_rejects_unsupported_san_type():
    logger = setup_logger()
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_cert = os.path.join(tmpdir, "ca.crt")
        ca_key = os.path.join(tmpdir, "ca.key")
        ca_pass = os.path.join(tmpdir, "pass")
        for p in [ca_cert, ca_key, ca_pass]:
            _write(p, b"x")
        args = argparse.Namespace(
            ca_cert=ca_cert,
            ca_key=ca_key,
            ca_pass_file=ca_pass,
            template="code_signing",
            subject="CN=Signer",
            san=["ip:127.0.0.1"],
            out_dir=tmpdir,
            validity_days=365,
            csr=None,
        )
        with pytest.raises(SystemExit):
            validate_issue_cert_args(args, logger)
