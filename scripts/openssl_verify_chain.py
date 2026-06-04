"""Optional OpenSSL interoperability check for Sprint 2.

Usage:
    python scripts/openssl_verify_chain.py \
      --root-cert ./pki/certs/ca.cert.pem \
      --intermediate-cert ./pki/certs/intermediate.cert.pem \
      --cert ./pki/certs/example.com.cert.pem
"""
import argparse
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-cert", required=True)
    parser.add_argument("--intermediate-cert", required=True)
    parser.add_argument("--cert", required=True)
    args = parser.parse_args()

    if shutil.which("openssl") is None:
        print("OpenSSL CLI is not available in PATH", file=sys.stderr)
        return 2

    checks = [
        ["openssl", "verify", "-CAfile", args.root_cert, args.intermediate_cert],
        ["openssl", "verify", "-CAfile", args.root_cert, "-untrusted", args.intermediate_cert, args.cert],
        ["openssl", "x509", "-in", args.cert, "-text", "-noout"],
    ]
    for command in checks:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout.decode(errors="replace"))
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
