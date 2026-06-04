#!/usr/bin/env python3
"""Automated Sprint 3 workflow demonstration.

The script creates a temporary PKI, initialises the DB, issues an Intermediate
CA and three leaf certificates, starts the repository server, fetches one leaf
certificate over HTTP, and verifies that the PEM matches the DB record.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import threading
import urllib.request

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from micropki.database import list_certificates
from micropki.repository import create_repository_server
from micropki.logger import setup_logger


def run(cmd, cwd):
    subprocess.run([sys.executable, "-m", "micropki", *cmd], cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", help="Optional working directory. Defaults to a temporary directory.")
    args = parser.parse_args()
    cleanup = args.work_dir is None
    work_dir = args.work_dir or tempfile.mkdtemp(prefix="micropki-sprint3-")
    os.makedirs(work_dir, exist_ok=True)
    pki = os.path.join(work_dir, "pki")
    secrets = os.path.join(work_dir, "secrets")
    os.makedirs(secrets, exist_ok=True)
    db_path = os.path.join(pki, "micropki.db")
    root_pass = os.path.join(secrets, "root.pass")
    inter_pass = os.path.join(secrets, "intermediate.pass")
    open(root_pass, "wb").write(b"rootpass")
    open(inter_pass, "wb").write(b"interpass")

    try:
        run(["db", "init", "--db-path", db_path], os.getcwd())
        run(["ca", "init", "--subject", "CN=Root CA,O=MicroPKI", "--key-type", "ecc", "--key-size", "384", "--passphrase-file", root_pass, "--out-dir", pki, "--db-path", db_path, "--force"], os.getcwd())
        run(["ca", "issue-intermediate", "--root-cert", os.path.join(pki, "certs", "ca.cert.pem"), "--root-key", os.path.join(pki, "private", "ca.key.pem"), "--root-pass-file", root_pass, "--subject", "CN=Intermediate CA,O=MicroPKI", "--key-type", "ecc", "--key-size", "384", "--passphrase-file", inter_pass, "--out-dir", pki, "--db-path", db_path], os.getcwd())
        for name in ["one.example.com", "two.example.com", "three.example.com"]:
            run(["ca", "issue-cert", "--ca-cert", os.path.join(pki, "certs", "intermediate.cert.pem"), "--ca-key", os.path.join(pki, "private", "intermediate.key.pem"), "--ca-pass-file", inter_pass, "--template", "server", "--subject", f"CN={name},O=MicroPKI", "--san", f"dns:{name}", "--out-dir", os.path.join(pki, "certs"), "--db-path", db_path], os.getcwd())

        leaf = [row for row in list_certificates(db_path) if "one.example.com" in row["subject"]][0]
        server = create_repository_server("127.0.0.1", 0, db_path, os.path.join(pki, "certs"), setup_logger())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/certificate/{leaf['serial_hex']}", timeout=5) as resp:
                body = resp.read().decode("ascii")
            if body != leaf["cert_pem"]:
                raise SystemExit("Repository PEM does not match DB PEM")
            print("Sprint 3 integration workflow: OK")
            print(f"Work directory: {work_dir}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        if cleanup:
            # Keep the path printed only when a user explicitly supplies one.
            pass


if __name__ == "__main__":
    main()
