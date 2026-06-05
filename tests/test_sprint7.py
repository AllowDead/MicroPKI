import argparse
import json
import os
import tempfile
import threading
import urllib.error
import urllib.request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from micropki.audit import AuditLogger, query_entries, verify_log
from micropki.ca import issue_cert
from micropki.certificates import load_private_key
from micropki.compromise import compromise_certificate
from micropki.database import get_compromised_key, list_certificates
from micropki.logger import setup_logger
from micropki.repository import create_repository_server
from micropki.transparency import certificate_in_ct_log

from tests.test_sprint3 import _issue_intermediate, _issue_leaf


def _csr_with_existing_key(subject, key_path, csr_path, san):
    key = load_private_key(key_path, None)
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject),
    ]))
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def _issue_leaf_result(pki, db_path, template="server", subject="CN=s7.example.com,O=MicroPKI", sans=None, validity_days=365, csr=None):
    args = argparse.Namespace(
        ca_cert=os.path.join(pki, "certs", "intermediate.cert.pem"),
        ca_key=os.path.join(pki, "private", "intermediate.key.pem"),
        ca_pass_file=os.path.join(os.path.dirname(pki), "intermediate.pass"),
        ca_passphrase_bytes=b"interpass",
        template=template,
        subject=None if csr else subject,
        san=[] if csr else (sans or ["dns:s7.example.com"]),
        out_dir=os.path.join(pki, "certs"),
        validity_days=validity_days,
        csr=csr,
        db_path=db_path,
    )
    return issue_cert(args, setup_logger())


def test_audit_hash_chain_detects_modified_entry():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        chain_file = os.path.join(tmpdir, "chain.dat")
        audit = AuditLogger(log_file, chain_file)
        audit.log_event("ca_init", "success", "created", metadata={"serial": "A1"})
        audit.log_event("issue_certificate", "success", "issued", metadata={"serial": "B2"})
        ok, _, _ = verify_log(log_file, chain_file)
        assert ok is True

        with open(log_file, "r+", encoding="utf-8") as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("issued", "issued-tampered", 1))
            f.truncate()

        ok, message, first = verify_log(log_file, chain_file)
        assert ok is False
        assert first == 2
        assert "hash mismatch" in message


def test_audit_query_filters_by_operation_and_serial():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        audit = AuditLogger(log_file, os.path.join(tmpdir, "chain.dat"))
        audit.log_event("issue_certificate", "success", "issued", metadata={"serial": "ABC"})
        audit.log_event("revoke_certificate", "success", "revoked", metadata={"serial": "ABC"})
        rows = query_entries(log_file, operation="issue", serial="ABC")
        assert len(rows) == 1
        assert rows[0]["operation"] == "issue_certificate"


def test_policy_rejects_excessive_leaf_validity_and_writes_audit():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        with pytest.raises(SystemExit):
            _issue_leaf_result(pki, db_path, validity_days=366)
        entries = query_entries(os.path.join(pki, "audit", "audit.log"), operation="policy_violation")
        assert any("validity" in row["message"] for row in entries)


def test_policy_rejects_wildcard_server_san_by_default():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        with pytest.raises(SystemExit):
            _issue_leaf_result(pki, db_path, subject="CN=wild.example.com,O=MicroPKI", sans=["dns:*.example.com"])
        entries = query_entries(os.path.join(pki, "audit", "audit.log"), operation="policy_violation")
        assert any("wildcard" in row["message"] for row in entries)


def test_ct_log_contains_issued_certificate():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        result = _issue_leaf_result(pki, db_path)
        assert certificate_in_ct_log(result["cert_path"], os.path.join(pki, "audit", "ct.log")) is True


def test_compromise_records_key_revokes_and_blocks_reuse():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        result = _issue_leaf_result(pki, db_path, subject="CN=compromised.example.com,O=MicroPKI", sans=["dns:compromised.example.com"])
        compromised = compromise_certificate(db_path, result["cert_path"], "keyCompromise", force=True, logger=setup_logger())
        row = [r for r in list_certificates(db_path) if r["serial_hex"] == compromised["serial_hex"]][0]
        assert row["status"] == "revoked"
        assert row["revocation_reason"] == "keyCompromise"
        assert get_compromised_key(db_path, compromised["public_key_hash"]) is not None

        csr_path = os.path.join(tmpdir, "reuse.csr.pem")
        _csr_with_existing_key("reuse.example.com", result["key_path"], csr_path, "reuse.example.com")
        with pytest.raises(SystemExit):
            _issue_leaf_result(pki, db_path, csr=csr_path)


def test_repository_rate_limiter_returns_429():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        server = create_repository_server(
            "127.0.0.1",
            0,
            db_path,
            os.path.join(pki, "certs"),
            setup_logger(),
            rate_limit=1,
            rate_burst=2,
        )
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        statuses = []
        try:
            for _ in range(5):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/ca/root", timeout=5) as response:
                        statuses.append(response.status)
                except urllib.error.HTTPError as exc:
                    statuses.append(exc.code)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert statuses[:2] == [200, 200]
        assert 429 in statuses[2:]
