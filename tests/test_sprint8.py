import argparse
import os
import socket
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509

from micropki.ca import issue_cert
from micropki.client import sign_file, validate_certificate_chain, verify_file_signature
from micropki.certificates import load_certificate
from micropki.crl import generate_crl
from micropki.database import list_certificates
from micropki.logger import setup_logger
from micropki.revocation import revoke_by_serial

from tests.test_sprint3 import _issue_intermediate, _issue_leaf


def _issue_leaf_result(pki, db_path, template, subject, sans=None, validity_days=365):
    args = argparse.Namespace(
        ca_cert=os.path.join(pki, "certs", "intermediate.cert.pem"),
        ca_key=os.path.join(pki, "private", "intermediate.key.pem"),
        ca_pass_file=os.path.join(os.path.dirname(pki), "intermediate.pass"),
        ca_passphrase_bytes=b"interpass",
        template=template,
        subject=subject,
        san=sans or [],
        out_dir=os.path.join(pki, "certs"),
        validity_days=validity_days,
        csr=None,
        db_path=db_path,
    )
    return issue_cert(args, setup_logger())


def test_wrong_key_usage_client_certificate_rejected_for_server_purpose():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        _issue_leaf(pki, db_path, "client", "CN=Wrong Purpose,EMAIL=wrong@example.com", ["email:wrong@example.com"])
        cert_path = os.path.join(pki, "certs", "Wrong_Purpose.cert.pem")
        root = os.path.join(pki, "certs", "ca.cert.pem")
        result = validate_certificate_chain(cert_path, [inter_cert], root, purpose="server")
        assert result.ok is False
        assert "EKU" in result.error or "server" in result.error


def test_malformed_certificate_file_fails_gracefully():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad = os.path.join(tmpdir, "bad.pem")
        open(bad, "w", encoding="utf-8").write("-----BEGIN CERTIFICATE-----\nnot-real\n-----END CERTIFICATE-----\n")
        with pytest.raises(Exception):
            load_certificate(bad)


def test_code_signing_signature_verifies_and_detects_tamper():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        result = _issue_leaf_result(pki, db_path, "code_signing", "CN=Code Signer,O=MicroPKI")
        script = os.path.join(tmpdir, "script.py")
        sig = os.path.join(tmpdir, "script.py.sig")
        open(script, "w", encoding="utf-8").write("print('signed')\n")

        sign_file(script, result["key_path"], sig, logger=setup_logger())
        assert verify_file_signature(
            script,
            sig,
            result["cert_path"],
            os.path.join(pki, "certs", "ca.cert.pem"),
            [inter_cert],
            logger=setup_logger(),
        ) is True

        open(script, "a", encoding="utf-8").write("print('tampered')\n")
        assert verify_file_signature(
            script,
            sig,
            result["cert_path"],
            os.path.join(pki, "certs", "ca.cert.pem"),
            [inter_cert],
            logger=setup_logger(),
        ) is False


def test_code_signing_verification_fails_when_signer_is_revoked_with_crl():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, inter_key, _ = _issue_intermediate(tmpdir, db_path)
        result = _issue_leaf_result(pki, db_path, "code_signing", "CN=Revoked Signer,O=MicroPKI")
        payload = os.path.join(tmpdir, "payload.txt")
        sig = os.path.join(tmpdir, "payload.sig")
        open(payload, "w", encoding="utf-8").write("payload\n")
        sign_file(payload, result["key_path"], sig)

        cert = load_certificate(result["cert_path"])
        serial = f"{cert.serial_number:X}"
        revoke_by_serial(db_path, serial, "keyCompromise", force=True, logger=setup_logger())
        crl_path = os.path.join(pki, "crl", "intermediate.crl.pem")
        generate_crl(db_path, inter_cert, inter_key, b"interpass", crl_path, 7, setup_logger())

        assert verify_file_signature(
            payload,
            sig,
            result["cert_path"],
            os.path.join(pki, "certs", "ca.cert.pem"),
            [inter_cert],
            crl=crl_path,
            issuer_cert_path=inter_cert,
            logger=setup_logger(),
        ) is False


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return


class _QuietTLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def test_tls_connection_succeeds_only_with_micro_pki_root_trust_anchor():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        result = _issue_leaf_result(
            pki,
            db_path,
            "server",
            "CN=localhost,O=MicroPKI",
            ["dns:localhost", "ip:127.0.0.1"],
        )
        chain_path = os.path.join(tmpdir, "localhost.chain.pem")
        with open(chain_path, "wb") as out:
            out.write(open(result["cert_path"], "rb").read())
            out.write(open(inter_cert, "rb").read())

        httpd = _QuietTLSServer(("127.0.0.1", 0), _QuietHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(chain_path, result["key_path"])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(ssl.SSLError):
                default_ctx = ssl.create_default_context()
                with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                    with default_ctx.wrap_socket(sock, server_hostname="localhost"):
                        pass

            client_ctx = ssl.create_default_context(cafile=os.path.join(pki, "certs", "ca.cert.pem"))
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                with client_ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                    tls.settimeout(3)
                    tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = tls.recv(128)
            assert b"HTTP/1." in data
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)


@pytest.mark.perf
def test_perf_issue_and_validate_1000_certificates():
    if os.environ.get("MICROPKI_RUN_PERF") != "1":
        pytest.skip("Set MICROPKI_RUN_PERF=1 and run pytest -m perf to execute the 1000-certificate performance test")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pki", "micropki.db")
        pki, inter_cert, _, _ = _issue_intermediate(tmpdir, db_path)
        root = os.path.join(pki, "certs", "ca.cert.pem")
        for idx in range(1000):
            _issue_leaf(pki, db_path, "server", f"CN=perf-{idx}.example.com,O=MicroPKI", [f"dns:perf-{idx}.example.com"])
        rows = [r for r in list_certificates(db_path) if "perf-" in r["subject"]]
        assert len(rows) == 1000
        for idx in range(1000):
            cert_path = os.path.join(pki, "certs", f"perf-{idx}.example.com.cert.pem")
            assert validate_certificate_chain(cert_path, [inter_cert], root, purpose="server").ok is True
