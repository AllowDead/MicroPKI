import argparse
import datetime as dt
import os
import tempfile
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from micropki.ca import issue_cert
from micropki.client import generate_csr, request_certificate, validate_certificate_chain, check_certificate_status
from micropki.crl import generate_crl
from micropki.database import list_certificates
from micropki.logger import setup_logger
from micropki.ocsp_responder import create_ocsp_server
from micropki.repository import create_repository_server
from micropki.revocation import revoke_by_serial

from tests.test_sprint3 import _issue_intermediate, _issue_leaf
from tests.test_sprint5 import _issue_ocsp


def _load_csr(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())


def _load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def test_client_gen_csr_saves_key_and_san():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "app.key.pem")
        csr_path = os.path.join(tmpdir, "app.csr.pem")
        generate_csr(
            "CN=app.example.com,O=MicroPKI",
            "rsa",
            2048,
            ["dns:app.example.com", "dns:api.example.com"],
            key_path,
            csr_path,
            setup_logger(),
        )
        assert os.path.isfile(key_path)
        assert os.path.isfile(csr_path)
        if os.name != "nt":
            assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"
        csr = _load_csr(csr_path)
        assert csr.is_signature_valid
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        assert "app.example.com" in san.get_values_for_type(x509.DNSName)
        assert "api.example.com" in san.get_values_for_type(x509.DNSName)


def test_ca_issue_cert_accepts_external_csr_and_uses_csr_subject_san():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, inter_key, _ = _issue_intermediate(tmpdir, db_path)
        csr_path = os.path.join(tmpdir, "csr.pem")
        key_path = os.path.join(tmpdir, "key.pem")
        generate_csr("CN=csr.example.com,O=MicroPKI", "rsa", 2048, ["dns:csr.example.com"], key_path, csr_path, setup_logger())
        args = argparse.Namespace(
            ca_cert=inter_cert,
            ca_key=inter_key,
            ca_pass_file=os.path.join(tmpdir, "intermediate.pass"),
            ca_passphrase_bytes=b"interpass",
            template="server",
            subject=None,
            san=[],
            out_dir=os.path.join(pki, "certs"),
            validity_days=365,
            csr=csr_path,
            db_path=db_path,
        )
        result = issue_cert(args, setup_logger())
        cert = _load_cert(result["cert_path"])
        assert cert.subject.rfc4514_string() == "O=MicroPKI,CN=csr.example.com"
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        assert san.get_values_for_type(x509.DNSName) == ["csr.example.com"]
        assert result["key_path"] is None


def test_repository_request_cert_endpoint_and_client_request_cert():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, inter_key, inter_pass = _issue_intermediate(tmpdir, db_path)
        key_path = os.path.join(tmpdir, "repo.key.pem")
        csr_path = os.path.join(tmpdir, "repo.csr.pem")
        out_cert = os.path.join(tmpdir, "repo.cert.pem")
        generate_csr("CN=request.example.com,O=MicroPKI", "rsa", 2048, ["dns:request.example.com"], key_path, csr_path, setup_logger())
        server = create_repository_server(
            "127.0.0.1",
            0,
            db_path,
            os.path.join(pki, "certs"),
            setup_logger(),
            ca_cert_path=inter_cert,
            ca_key_path=inter_key,
            ca_pass_file=inter_pass,
            api_key="changeme",
        )
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request_certificate(csr_path, "server", f"http://127.0.0.1:{port}", out_cert, api_key="changeme", logger=setup_logger())
            cert = _load_cert(out_cert)
            assert cert.subject.rfc4514_string() == "O=MicroPKI,CN=request.example.com"
            assert any("request.example.com" in row["subject"] for row in list_certificates(db_path))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_client_validate_valid_chain_and_missing_intermediate():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "server", "CN=valid.example.com,O=MicroPKI", ["dns:valid.example.com"])
        leaf = os.path.join(pki, "certs", "valid.example.com.cert.pem")
        root = os.path.join(pki, "certs", "ca.cert.pem")
        ok = validate_certificate_chain(leaf, [inter_cert], root, purpose="server")
        assert ok.ok is True
        missing = validate_certificate_chain(leaf, [], root, purpose="server")
        assert missing.ok is False
        assert "Could not build" in missing.error


def test_client_validate_expired_by_validation_time():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "server", "CN=expire.example.com,O=MicroPKI", ["dns:expire.example.com"])
        leaf = os.path.join(pki, "certs", "expire.example.com.cert.pem")
        root = os.path.join(pki, "certs", "ca.cert.pem")
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5000)
        result = validate_certificate_chain(leaf, [inter_cert], root, purpose="server", validation_time=future)
        assert result.ok is False
        assert "expired" in result.error


def test_client_check_status_crl_only_reports_revoked():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, inter_key, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "server", "CN=revoked-crl.example.com,O=MicroPKI", ["dns:revoked-crl.example.com"])
        row = [r for r in list_certificates(db_path) if "revoked-crl" in r["subject"]][0]
        revoke_by_serial(db_path, row["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        crl_path = os.path.join(pki, "crl", "intermediate.crl.pem")
        generate_crl(db_path, inter_cert, inter_key, b"interpass", crl_path, 7, setup_logger())
        status = check_certificate_status(os.path.join(pki, "certs", "revoked-crl.example.com.cert.pem"), inter_cert, crl=crl_path, logger=setup_logger())
        assert status.status == "revoked"
        assert status.source == "crl"


def test_client_check_status_ocsp_and_fallback_to_crl():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, inter_key, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "server", "CN=revoked-ocsp.example.com,O=MicroPKI", ["dns:revoked-ocsp.example.com"])
        row = [r for r in list_certificates(db_path) if "revoked-ocsp" in r["subject"]][0]
        leaf = os.path.join(pki, "certs", "revoked-ocsp.example.com.cert.pem")
        revoke_by_serial(db_path, row["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        ocsp_cert, ocsp_key = _issue_ocsp(pki, db_path)
        server = create_ocsp_server("127.0.0.1", 0, db_path, ocsp_cert, ocsp_key, inter_cert, logger=setup_logger())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status = check_certificate_status(leaf, inter_cert, ocsp_url=f"http://127.0.0.1:{port}/ocsp", logger=setup_logger())
            assert status.status == "revoked"
            assert status.source == "ocsp"
        finally:
            # Avoid rare BaseServer.shutdown blocking on heavily loaded Windows/Linux CI.
            server.server_close()

        crl_path = os.path.join(pki, "crl", "intermediate.crl.pem")
        generate_crl(db_path, inter_cert, inter_key, b"interpass", crl_path, 7, setup_logger())
        fallback = check_certificate_status(leaf, inter_cert, crl=crl_path, ocsp_url="http://127.0.0.1:1/ocsp", logger=setup_logger())
        assert fallback.status == "revoked"
        assert fallback.source == "crl"
