#!/usr/bin/env python3
"""Self-contained Sprint 8 demonstration for MicroPKI.

The script creates a complete temporary PKI, starts repository/OCSP services,
validates certificates, demonstrates TLS, revocation, audit verification,
policy enforcement, and code signing. It is intentionally idempotent: the work
folder is removed before every run unless --keep is supplied.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A003 - stdlib API
        return


class DemoTLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def cert_serial(path: Path) -> str:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return f"{cert.serial_number:X}"


def run(cmd: list[str], cwd: Path, expect_ok: bool = True) -> subprocess.CompletedProcess:
    print("$ " + " ".join(str(c) for c in cmd))
    completed = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=30)
    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.stderr.strip():
        print(completed.stderr.strip())
    if expect_ok and completed.returncode != 0:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {' '.join(cmd)}")
    if not expect_ok and completed.returncode == 0:
        raise RuntimeError(f"command unexpectedly succeeded: {' '.join(cmd)}")
    print("[PASS]" if (completed.returncode == 0) == expect_ok else "[FAIL]")
    return completed


def wait_for_tcp(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"service did not start on 127.0.0.1:{port}")


def tls_probe(port: int, cafile: Path | None) -> bool:
    context = ssl.create_default_context(cafile=str(cafile)) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.settimeout(3)
                tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = tls.recv(128)
                return b"HTTP/1." in data
    except ssl.SSLError:
        return False


def start_tls_server(chain_file: Path, key_file: Path) -> tuple[DemoTLSServer, threading.Thread, int]:
    server = DemoTLSServer(("127.0.0.1", 0), QuietHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(chain_file), str(key_file))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the complete MicroPKI Sprint 8 demo")
    parser.add_argument("--work-dir", default="demo/_work", help="Work directory. It is cleaned before the demo unless --keep is used.")
    parser.add_argument("--keep", action="store_true", help="Keep the work directory after the run")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    work = (repo_root / args.work_dir).resolve()
    if work.exists() and not args.keep:
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    (work / "secrets").mkdir(exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    (work / "demo-files").mkdir(exist_ok=True)
    (work / "secrets" / "root.pass").write_text("root-passphrase\n", encoding="utf-8")
    (work / "secrets" / "intermediate.pass").write_text("intermediate-passphrase\n", encoding="utf-8")

    py = sys.executable
    base = [py, "-m", "micropki"]
    pki = work / "pki"
    db = pki / "micropki.db"
    root_cert = pki / "certs" / "ca.cert.pem"
    root_key = pki / "private" / "ca.key.pem"
    inter_cert = pki / "certs" / "intermediate.cert.pem"
    inter_key = pki / "private" / "intermediate.key.pem"
    root_pass = work / "secrets" / "root.pass"
    inter_pass = work / "secrets" / "intermediate.pass"
    crl = pki / "crl" / "intermediate.crl.pem"

    repo_proc = None
    ocsp_proc = None
    tls_server = None
    tls_thread = None
    try:
        print("\n== 1. CA setup ==")
        run(base + ["ca", "init", "--subject", "CN=Demo Root CA,O=MicroPKI", "--key-type", "ecc", "--key-size", "384", "--passphrase-file", str(root_pass), "--out-dir", str(pki), "--db-path", str(db), "--force"], repo_root)
        run(base + ["ca", "issue-intermediate", "--root-cert", str(root_cert), "--root-key", str(root_key), "--root-pass-file", str(root_pass), "--subject", "CN=Demo Intermediate CA,O=MicroPKI", "--key-type", "ecc", "--key-size", "384", "--passphrase-file", str(inter_pass), "--out-dir", str(pki), "--db-path", str(db)], repo_root)

        print("\n== 2. Certificate issuance ==")
        run(base + ["ca", "issue-cert", "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--template", "server", "--subject", "CN=localhost,O=MicroPKI", "--san", "dns:localhost", "--san", "ip:127.0.0.1", "--out-dir", str(pki / "certs"), "--db-path", str(db)], repo_root)
        run(base + ["ca", "issue-cert", "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--template", "client", "--subject", "CN=Demo Client,EMAIL=client@example.com", "--san", "email:client@example.com", "--out-dir", str(pki / "certs"), "--db-path", str(db)], repo_root)
        run(base + ["ca", "issue-cert", "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--template", "code_signing", "--subject", "CN=Demo Code Signer,O=MicroPKI", "--out-dir", str(pki / "certs"), "--db-path", str(db)], repo_root)
        run(base + ["ca", "issue-ocsp-cert", "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--subject", "CN=Demo OCSP Responder,O=MicroPKI", "--san", "dns:ocsp.local", "--out-dir", str(pki / "certs"), "--db-path", str(db)], repo_root)

        print("\n== 3. Start repository and OCSP responders ==")
        repo_port = free_port()
        ocsp_port = free_port()
        repo_proc = subprocess.Popen(base + ["repo", "serve", "--host", "127.0.0.1", "--port", str(repo_port), "--db-path", str(db), "--cert-dir", str(pki / "certs"), "--crl-dir", str(pki / "crl"), "--rate-limit", "10", "--rate-burst", "20", "--log-file", str(work / "logs" / "repo.log")], cwd=repo_root)
        ocsp_proc = subprocess.Popen(base + ["ocsp", "serve", "--host", "127.0.0.1", "--port", str(ocsp_port), "--db-path", str(db), "--responder-cert", str(pki / "certs" / "ocsp.cert.pem"), "--responder-key", str(pki / "certs" / "ocsp.key.pem"), "--ca-cert", str(inter_cert), "--rate-limit", "10", "--rate-burst", "20", "--log-file", str(work / "logs" / "ocsp.log")], cwd=repo_root)
        wait_for_tcp(repo_port)
        wait_for_tcp(ocsp_port)
        urllib.request.urlopen(f"http://127.0.0.1:{repo_port}/ca/root", timeout=5).read()
        print("[PASS] repository and OCSP services are running")

        server_cert = pki / "certs" / "localhost.cert.pem"
        server_key = pki / "certs" / "localhost.key.pem"
        print("\n== 4. Validation and revocation checks ==")
        run(base + ["client", "validate", "--cert", str(server_cert), "--untrusted", str(inter_cert), "--trusted", str(root_cert), "--purpose", "server", "--ocsp-url", f"http://127.0.0.1:{ocsp_port}/ocsp", "--ca-cert", str(inter_cert)], repo_root)

        print("\n== 5. TLS demonstration ==")
        chain_file = work / "demo-files" / "localhost.chain.pem"
        chain_file.write_bytes(server_cert.read_bytes() + inter_cert.read_bytes())
        tls_server, tls_thread, tls_port = start_tls_server(chain_file, server_key)
        if tls_probe(tls_port, None):
            raise RuntimeError("TLS unexpectedly succeeded without the MicroPKI root trust anchor")
        if not tls_probe(tls_port, root_cert):
            raise RuntimeError("TLS failed even when the MicroPKI root trust anchor was supplied")
        print("[PASS] TLS fails without Root CA and succeeds with Root CA")

        print("\n== 6. Code signing demonstration ==")
        sample = work / "demo-files" / "sample_app.py"
        sig = work / "demo-files" / "sample_app.py.sig"
        sample.write_text("print('hello from signed MicroPKI demo')\n", encoding="utf-8")
        signer_cert = pki / "certs" / "Demo_Code_Signer.cert.pem"
        signer_key = pki / "certs" / "Demo_Code_Signer.key.pem"
        run(base + ["client", "sign", "--input", str(sample), "--key", str(signer_key), "--signature", str(sig)], repo_root)
        run(base + ["client", "verify-signature", "--input", str(sample), "--signature", str(sig), "--cert", str(signer_cert), "--trusted", str(root_cert), "--untrusted", str(inter_cert)], repo_root)
        sample.write_text(sample.read_text(encoding="utf-8") + "# tamper\n", encoding="utf-8")
        run(base + ["client", "verify-signature", "--input", str(sample), "--signature", str(sig), "--cert", str(signer_cert), "--trusted", str(root_cert), "--untrusted", str(inter_cert)], repo_root, expect_ok=False)

        print("\n== 7. Policy enforcement ==")
        run(base + ["ca", "issue-cert", "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--template", "server", "--subject", "CN=wild.example.com,O=MicroPKI", "--san", "dns:*.example.com", "--out-dir", str(pki / "certs"), "--db-path", str(db)], repo_root, expect_ok=False)

        print("\n== 8. Revoke server certificate and prove revocation blocks validation ==")
        serial = cert_serial(server_cert)
        run(base + ["ca", "revoke", serial, "--reason", "keyCompromise", "--force", "--crl", str(crl), "--ca-cert", str(inter_cert), "--ca-key", str(inter_key), "--ca-pass-file", str(inter_pass), "--out-dir", str(pki), "--db-path", str(db)], repo_root)
        run(base + ["client", "validate", "--cert", str(server_cert), "--untrusted", str(inter_cert), "--trusted", str(root_cert), "--purpose", "server", "--crl", str(crl), "--ca-cert", str(inter_cert)], repo_root, expect_ok=False)

        print("\n== 9. Audit and CT verification ==")
        run(base + ["audit", "verify", "--log-file", str(pki / "audit" / "audit.log"), "--chain-file", str(pki / "audit" / "chain.dat")], repo_root)
        run(base + ["audit", "ct-verify", "--cert", str(server_cert), "--ct-log", str(pki / "audit" / "ct.log")], repo_root)

        print("\nSprint 8 demo completed successfully.")
        return 0
    finally:
        if tls_server is not None:
            tls_server.shutdown()
            tls_server.server_close()
        if tls_thread is not None:
            tls_thread.join(timeout=3)
        for proc in (repo_proc, ocsp_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
