"""Optional Sprint 2 TLS round-trip smoke test using OpenSSL.

The script starts openssl s_server with the issued server certificate and
connects to it with openssl s_client trusting the Root CA.

Usage:
    python scripts/tls_roundtrip.py \
      --root-cert ./pki/certs/ca.cert.pem \
      --chain-cert ./pki/certs/intermediate.cert.pem \
      --server-cert ./pki/certs/example.com.cert.pem \
      --server-key ./pki/certs/example.com.key.pem
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-cert", required=True)
    parser.add_argument("--chain-cert", required=True)
    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)
    args = parser.parse_args()

    if shutil.which("openssl") is None:
        print("OpenSSL CLI is not available in PATH", file=sys.stderr)
        return 2

    for path in [args.root_cert, args.chain_cert, args.server_cert, args.server_key]:
        if not os.path.exists(path):
            print(f"Missing file: {path}", file=sys.stderr)
            return 2

    port = _free_port()
    with tempfile.NamedTemporaryFile("wb", delete=False) as chain_file:
        with open(args.chain_cert, "rb") as f:
            chain_file.write(f.read())
        chain_path = chain_file.name

    server = subprocess.Popen(
        [
            "openssl", "s_server",
            "-accept", str(port),
            "-cert", args.server_cert,
            "-key", args.server_key,
            "-cert_chain", chain_path,
            "-www",
            "-quiet",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        client = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"127.0.0.1:{port}",
                "-CAfile", args.root_cert,
                "-verify_return_error",
                "-servername", "example.com",
            ],
            input=b"Q\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
        output = client.stdout.decode(errors="replace")
        if client.returncode == 0 and "Verify return code: 0 (ok)" in output:
            print("TLS round-trip: OK")
            return 0
        print(output)
        return 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
        try:
            os.unlink(chain_path)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
