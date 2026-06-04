import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from micropki.crl import generate_crl, load_crl
from micropki.database import get_certificate_by_serial, get_crl_metadata, list_certificates
from micropki.logger import setup_logger
from micropki.repository import create_repository_server
from micropki.revocation import normalize_reason, reason_to_flag, revoke_by_serial

from tests.test_sprint3 import _issue_intermediate, _issue_leaf


def _prepare_revoked_leaf(tmpdir):
    db_path = os.path.join(tmpdir, "pki", "micropki.db")
    pki, inter_cert, inter_key, inter_pass = _issue_intermediate(tmpdir, db_path)
    _issue_leaf(pki, db_path, "server", "CN=revoked.example.com,O=MicroPKI", ["dns:revoked.example.com"])
    leaf = [r for r in list_certificates(db_path) if "revoked.example.com" in r["subject"]][0]
    return pki, db_path, inter_cert, inter_key, inter_pass, leaf


def _crl_number(crl):
    return crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER).value.crl_number


def test_reason_code_mapping_supports_required_values():
    reasons = [
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise",
    ]
    for reason in reasons:
        assert normalize_reason(reason) == reason
        assert reason_to_flag(reason) is not None
    with pytest.raises(ValueError):
        normalize_reason("badReason")


def test_revocation_lifecycle_generates_crl_and_updates_database():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki, db_path, inter_cert, inter_key, _, leaf = _prepare_revoked_leaf(tmpdir)
        assert leaf["status"] == "valid"
        updated = revoke_by_serial(db_path, leaf["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        assert updated["status"] == "revoked"
        assert updated["revocation_reason"] == "keyCompromise"
        assert updated["revocation_date"]

        out_file = os.path.join(pki, "crl", "intermediate.crl.pem")
        result = generate_crl(db_path, inter_cert, inter_key, b"interpass", out_file, 7, setup_logger())
        assert result.revoked_count == 1
        assert os.path.isfile(out_file)
        assert open(out_file, "rb").read().startswith(b"-----BEGIN X509 CRL-----")

        crl = load_crl(out_file)
        entries = list(crl)
        assert len(entries) == 1
        assert entries[0].serial_number == int(leaf["serial_hex"], 16)
        reason = entries[0].extensions.get_extension_for_class(x509.CRLReason).value.reason
        assert reason == x509.ReasonFlags.key_compromise
        assert get_crl_metadata(db_path, result.ca_subject)["crl_number"] == 1


def test_crl_number_increments_across_invocations():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki, db_path, inter_cert, inter_key, _, _ = _prepare_revoked_leaf(tmpdir)
        first = os.path.join(pki, "crl", "intermediate.crl.pem")
        second = os.path.join(pki, "crl", "intermediate-2.crl.pem")
        r1 = generate_crl(db_path, inter_cert, inter_key, b"interpass", first, 7, setup_logger())
        r2 = generate_crl(db_path, inter_cert, inter_key, b"interpass", second, 7, setup_logger())
        assert r2.crl_number == r1.crl_number + 1
        assert _crl_number(load_crl(second)) == _crl_number(load_crl(first)) + 1


def test_revoke_missing_and_already_revoked_behaviour():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki, db_path, inter_cert, inter_key, _, leaf = _prepare_revoked_leaf(tmpdir)
        with pytest.raises(KeyError):
            revoke_by_serial(db_path, "ABCDEF", "keyCompromise", force=True, logger=setup_logger())
        first = revoke_by_serial(db_path, leaf["serial_hex"], "superseded", force=True, logger=setup_logger())
        second = revoke_by_serial(db_path, leaf["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        assert second["revocation_reason"] == first["revocation_reason"] == "superseded"
        assert get_certificate_by_serial(db_path, leaf["serial_hex"])["status"] == "revoked"


def test_repository_serves_generated_crl_with_headers():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki, db_path, inter_cert, inter_key, _, leaf = _prepare_revoked_leaf(tmpdir)
        revoke_by_serial(db_path, leaf["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        crl_path = os.path.join(pki, "crl", "intermediate.crl.pem")
        generate_crl(db_path, inter_cert, inter_key, b"interpass", crl_path, 7, setup_logger())
        expected = open(crl_path, "rb").read()

        server = create_repository_server("127.0.0.1", 0, db_path, os.path.join(pki, "certs"), setup_logger(), os.path.join(pki, "crl"))
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{port}"
            with urllib.request.urlopen(f"{base}/crl?ca=intermediate", timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers["Content-Type"] == "application/pkix-crl"
                assert resp.headers["Access-Control-Allow-Origin"] == "*"
                assert "Last-Modified" in resp.headers
                assert "Cache-Control" in resp.headers
                assert "ETag" in resp.headers
                assert resp.read() == expected
            with urllib.request.urlopen(f"{base}/crl/intermediate.crl", timeout=5) as resp:
                assert resp.status == 200
                assert resp.read() == expected
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI is not installed")
def test_openssl_verifies_generated_crl_signature():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki, db_path, inter_cert, inter_key, _, leaf = _prepare_revoked_leaf(tmpdir)
        revoke_by_serial(db_path, leaf["serial_hex"], "keyCompromise", force=True, logger=setup_logger())
        crl_path = os.path.join(pki, "crl", "intermediate.crl.pem")
        generate_crl(db_path, inter_cert, inter_key, b"interpass", crl_path, 7, setup_logger())
        result = subprocess.run(
            ["openssl", "crl", "-in", crl_path, "-inform", "PEM", "-CAfile", inter_cert, "-noout"],
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
