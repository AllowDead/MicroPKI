import argparse
import os
import subprocess
import sys
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives import serialization

from micropki.ca import issue_cert, issue_intermediate
from micropki.certificates import build_ca_certificate, generate_key
from micropki.database import (
    certificate_to_record,
    get_certificate_by_serial,
    init_database,
    insert_certificate_record,
    list_certificates,
    list_revoked_certificates,
    normalize_serial_hex,
    schema_is_initialized,
    update_certificate_status,
)
from micropki.crypto_utils import parse_dn
from micropki.logger import setup_logger
from micropki.repository import create_repository_server
from micropki.serial import generate_unique_serial


def _write(path, data):
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    kwargs = {} if "b" in mode else {"encoding": "utf-8"}
    with open(path, mode, **kwargs) as f:
        f.write(data)


def _pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _encrypted_key(key, password=b"pass"):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def _prepare_root_pki(tmpdir):
    root_key = generate_key("ecc", 384)
    root_cert = build_ca_certificate(parse_dn("CN=Root CA,O=MicroPKI"), root_key, 3650)
    pki = os.path.join(tmpdir, "pki")
    os.makedirs(os.path.join(pki, "certs"), exist_ok=True)
    os.makedirs(os.path.join(pki, "private"), exist_ok=True)
    os.makedirs(os.path.join(pki, "csrs"), exist_ok=True)
    root_cert_path = os.path.join(pki, "certs", "ca.cert.pem")
    root_key_path = os.path.join(pki, "private", "ca.key.pem")
    root_pass_path = os.path.join(tmpdir, "root.pass")
    _write(root_cert_path, _pem_cert(root_cert))
    _write(root_key_path, _encrypted_key(root_key, b"rootpass"))
    _write(root_pass_path, b"rootpass")
    _write(os.path.join(pki, "policy.txt"), "Policy\n")
    return pki, root_cert_path, root_key_path, root_pass_path


def _issue_intermediate(tmpdir, db_path):
    logger = setup_logger()
    pki, root_cert_path, root_key_path, root_pass_path = _prepare_root_pki(tmpdir)
    inter_pass_path = os.path.join(tmpdir, "intermediate.pass")
    _write(inter_pass_path, b"interpass")
    args = argparse.Namespace(
        root_cert=root_cert_path,
        root_key=root_key_path,
        root_pass_file=root_pass_path,
        root_passphrase_bytes=b"rootpass",
        subject="CN=Intermediate CA,O=MicroPKI",
        key_type="ecc",
        key_size=384,
        passphrase_file=inter_pass_path,
        passphrase_bytes=b"interpass",
        out_dir=pki,
        validity_days=1825,
        pathlen=0,
        db_path=db_path,
    )
    issue_intermediate(args, logger)
    return pki, os.path.join(pki, "certs", "intermediate.cert.pem"), os.path.join(pki, "private", "intermediate.key.pem"), inter_pass_path


def _issue_leaf(pki, db_path, template, subject, sans):
    logger = setup_logger()
    args = argparse.Namespace(
        ca_cert=os.path.join(pki, "certs", "intermediate.cert.pem"),
        ca_key=os.path.join(pki, "private", "intermediate.key.pem"),
        ca_pass_file=os.path.join(os.path.dirname(pki), "intermediate.pass"),
        ca_passphrase_bytes=b"interpass",
        template=template,
        subject=subject,
        san=sans,
        out_dir=os.path.join(pki, "certs"),
        validity_days=365,
        csr=None,
        db_path=db_path,
    )
    issue_cert(args, logger)


def test_db_init_schema_is_idempotent():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "micropki.db")
        init_database(db_path)
        init_database(db_path)
        assert schema_is_initialized(db_path) is True


def test_unique_serial_generator_and_duplicate_constraint():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "micropki.db")
        init_database(db_path)
        serials = {normalize_serial_hex(generate_unique_serial(db_path)) for _ in range(100)}
        assert len(serials) == 100

        key = generate_key("ecc", 384)
        cert = build_ca_certificate(parse_dn("CN=Duplicate Test"), key, 365, serial_number=int(next(iter(serials)), 16))
        record = certificate_to_record(cert)
        insert_certificate_record(db_path, record)
        with pytest.raises(sqlite3.IntegrityError):
            insert_certificate_record(db_path, record)


def test_issue_five_certificates_are_inserted_and_retrievable():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        specs = [
            ("server", "CN=one.example.com,O=MicroPKI", ["dns:one.example.com"]),
            ("server", "CN=two.example.com,O=MicroPKI", ["dns:two.example.com", "ip:127.0.0.1"]),
            ("client", "CN=Alice,EMAIL=alice@example.com", ["email:alice@example.com"]),
            ("client", "CN=Bob,EMAIL=bob@example.com", ["email:bob@example.com"]),
            ("code_signing", "CN=MicroPKI Signer", []),
        ]
        for spec in specs:
            _issue_leaf(pki, db_path, *spec)

        records = list_certificates(db_path)
        # 1 intermediate + 5 leaf certificates are auto-inserted.
        assert len(records) == 6
        serials = [row["serial_hex"] for row in records]
        assert len(serials) == len(set(serials))
        assert any("CN=one.example.com" in row["subject"] for row in records)
        fetched = get_certificate_by_serial(db_path, serials[0])
        assert fetched["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")


def test_status_update_and_revoked_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        rows = list_certificates(db_path)
        serial = rows[0]["serial_hex"]
        assert update_certificate_status(db_path, serial, "revoked", "keyCompromise") is True
        revoked = list_revoked_certificates(db_path)
        assert len(revoked) == 1
        assert revoked[0]["serial_hex"] == serial
        assert revoked[0]["revocation_reason"] == "keyCompromise"


def test_repository_api_fetches_certificate_ca_and_handles_errors():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "server", "CN=repo.example.com,O=MicroPKI", ["dns:repo.example.com"])
        leaf = [row for row in list_certificates(db_path) if "repo.example.com" in row["subject"]][0]

        server = create_repository_server("127.0.0.1", 0, db_path, os.path.join(pki, "certs"), setup_logger())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{port}"
            with urllib.request.urlopen(f"{base}/certificate/{leaf['serial_hex']}", timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers["Access-Control-Allow-Origin"] == "*"
                assert resp.read().decode("ascii") == leaf["cert_pem"]
            with urllib.request.urlopen(f"{base}/ca/root", timeout=5) as resp:
                assert resp.status == 200
                assert resp.read().startswith(b"-----BEGIN CERTIFICATE-----")
            with urllib.request.urlopen(f"{base}/ca/intermediate", timeout=5) as resp:
                assert resp.status == 200
                assert resp.read().startswith(b"-----BEGIN CERTIFICATE-----")
            with pytest.raises(urllib.error.HTTPError) as bad_serial:
                urllib.request.urlopen(f"{base}/certificate/XYZ", timeout=5)
            assert bad_serial.value.code == 400
            with pytest.raises(urllib.error.HTTPError) as crl:
                urllib.request.urlopen(f"{base}/crl", timeout=5)
            assert crl.value.code == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)



def test_cli_list_and_show_cert_retrieve_database_records():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, _, _, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "client", "CN=Cli Alice,EMAIL=cli@example.com", ["email:cli@example.com"])
        rows = list_certificates(db_path)
        leaf = [row for row in rows if "Cli Alice" in row["subject"]][0]

        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
        listed = subprocess.run(
            [sys.executable, "-m", "micropki", "ca", "list-certs", "--db-path", db_path, "--format", "table"],
            cwd=os.getcwd(),
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        assert "Cli Alice" in listed.stdout
        assert leaf["serial_hex"] in listed.stdout

        shown = subprocess.run(
            [sys.executable, "-m", "micropki", "ca", "show-cert", leaf["serial_hex"], "--db-path", db_path],
            cwd=os.getcwd(),
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        assert shown.stdout == leaf["cert_pem"]
