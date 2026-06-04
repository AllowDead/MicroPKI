import argparse
import os
import shutil
import subprocess
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from micropki.ca import issue_ocsp_cert
from micropki.certificates import load_certificate
from micropki.database import list_certificates
from micropki.logger import setup_logger
from micropki.ocsp import issuer_hashes, load_ocsp_private_key, process_ocsp_request
from micropki.revocation import revoke_by_serial

from tests.test_sprint3 import _issue_intermediate, _issue_leaf


def _load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _issue_ocsp(pki, db_path):
    args = argparse.Namespace(
        ca_cert=os.path.join(pki, "certs", "intermediate.cert.pem"),
        ca_key=os.path.join(pki, "private", "intermediate.key.pem"),
        ca_pass_file=os.path.join(os.path.dirname(pki), "intermediate.pass"),
        ca_passphrase_bytes=b"interpass",
        subject="CN=OCSP Responder,O=MicroPKI",
        key_type="ecc",
        key_size=256,
        san=["dns:ocsp.example.com"],
        out_dir=os.path.join(pki, "certs"),
        validity_days=365,
        db_path=db_path,
    )
    issue_ocsp_cert(args, setup_logger())
    return os.path.join(pki, "certs", "ocsp.cert.pem"), os.path.join(pki, "certs", "ocsp.key.pem")


def _prepare_ocsp_workflow(tmpdir):
    db_path = os.path.join(tmpdir, "pki", "micropki.db")
    pki, inter_cert_path, inter_key_path, _ = _issue_intermediate(tmpdir, db_path)
    _issue_leaf(pki, db_path, "server", "CN=ocsp-good.example.com,O=MicroPKI", ["dns:ocsp-good.example.com"])
    leaf_row = [r for r in list_certificates(db_path) if "ocsp-good.example.com" in r["subject"]][0]
    leaf_cert_path = os.path.join(pki, "certs", "ocsp-good.example.com.cert.pem")
    ocsp_cert_path, ocsp_key_path = _issue_ocsp(pki, db_path)
    return pki, db_path, inter_cert_path, inter_key_path, leaf_cert_path, leaf_row, ocsp_cert_path, ocsp_key_path


def _ocsp_request(cert_path, issuer_path, nonce=None):
    cert = _load_cert(cert_path)
    issuer = _load_cert(issuer_path)
    builder = crypto_ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def _unknown_ocsp_request(issuer_path, serial=0xABCDEF):
    issuer = _load_cert(issuer_path)
    name_hash, key_hash = issuer_hashes(issuer, hashes.SHA1())
    req = crypto_ocsp.OCSPRequestBuilder().add_certificate_by_hash(name_hash, key_hash, serial, hashes.SHA1()).build()
    return req.public_bytes(serialization.Encoding.DER)


def _process(db_path, inter_cert, ocsp_cert, ocsp_key, body):
    return process_ocsp_request(
        body,
        db_path,
        load_certificate(inter_cert),
        load_certificate(ocsp_cert),
        load_ocsp_private_key(ocsp_key),
        60,
        setup_logger(),
        "127.0.0.1",
    )


def test_ocsp_signer_certificate_profile():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, db_path, _, _, _, _, ocsp_cert_path, ocsp_key_path = _prepare_ocsp_workflow(tmpdir)
        cert = _load_cert(ocsp_cert_path)
        assert os.path.isfile(ocsp_key_path)
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is False
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        assert ku.digital_signature is True
        assert ku.key_cert_sign is False
        assert ku.crl_sign is False
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        assert list(eku) == [ExtendedKeyUsageOID.OCSP_SIGNING]
        assert any("OCSP Responder" in row["subject"] for row in list_certificates(db_path))


def test_ocsp_good_response_echoes_nonce_and_signature_is_parseable():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, db_path, inter_cert, _, leaf_cert, _, ocsp_cert, ocsp_key = _prepare_ocsp_workflow(tmpdir)
        nonce = b"micro-pki-nonce"
        status, body, content_type, _ = _process(db_path, inter_cert, ocsp_cert, ocsp_key, _ocsp_request(leaf_cert, inter_cert, nonce=nonce))
        assert status == 200
        assert content_type == "application/ocsp-response"
        response = crypto_ocsp.load_der_ocsp_response(body)
        assert response.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL
        assert response.certificate_status == crypto_ocsp.OCSPCertStatus.GOOD
        assert response.serial_number == _load_cert(leaf_cert).serial_number
        assert response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce == nonce


def test_ocsp_request_without_nonce_has_no_nonce_extension():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, db_path, inter_cert, _, leaf_cert, _, ocsp_cert, ocsp_key = _prepare_ocsp_workflow(tmpdir)
        _, body, _, _ = _process(db_path, inter_cert, ocsp_cert, ocsp_key, _ocsp_request(leaf_cert, inter_cert))
        response = crypto_ocsp.load_der_ocsp_response(body)
        assert response.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL
        with pytest.raises(x509.ExtensionNotFound):
            response.extensions.get_extension_for_class(x509.OCSPNonce)


def test_ocsp_revoked_and_unknown_statuses():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, db_path, inter_cert, _, leaf_cert, leaf_row, ocsp_cert, ocsp_key = _prepare_ocsp_workflow(tmpdir)
        revoke_by_serial(db_path, leaf_row["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        _, revoked_body, _, _ = _process(db_path, inter_cert, ocsp_cert, ocsp_key, _ocsp_request(leaf_cert, inter_cert))
        revoked = crypto_ocsp.load_der_ocsp_response(revoked_body)
        assert revoked.certificate_status == crypto_ocsp.OCSPCertStatus.REVOKED
        assert revoked.revocation_reason == x509.ReasonFlags.key_compromise
        _, unknown_body, _, _ = _process(db_path, inter_cert, ocsp_cert, ocsp_key, _unknown_ocsp_request(inter_cert))
        unknown = crypto_ocsp.load_der_ocsp_response(unknown_body)
        assert unknown.certificate_status == crypto_ocsp.OCSPCertStatus.UNKNOWN


def test_ocsp_malformed_request_errors():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, db_path, inter_cert, _, _, _, ocsp_cert, ocsp_key = _prepare_ocsp_workflow(tmpdir)
        status, body, _, _ = _process(db_path, inter_cert, ocsp_cert, ocsp_key, b"garbage")
        assert status == 400
        response = crypto_ocsp.load_der_ocsp_response(body)
        assert response.response_status == crypto_ocsp.OCSPResponseStatus.MALFORMED_REQUEST


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI is not installed")
def test_openssl_can_inspect_ocsp_signer_certificate():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, _, _, _, _, _, ocsp_cert, _ = _prepare_ocsp_workflow(tmpdir)
        result = subprocess.run(["openssl", "x509", "-in", ocsp_cert, "-text", "-noout"], text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert "OCSP Signing" in result.stdout
