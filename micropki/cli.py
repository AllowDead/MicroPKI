import argparse
import os
import stat
import sys


def _nearest_existing_parent(path):
    candidate = os.path.abspath(path)
    while not os.path.exists(candidate):
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    return candidate


def _is_writable_directory(path):
    """Return True only when a directory is writable for normal use."""
    if not os.path.isdir(path):
        return False

    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o222 == 0:
            return False

    return os.access(path, os.W_OK)


def _validate_common_out_dir(path, errors):
    out_dir = os.path.abspath(path)
    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        errors.append(f"--out-dir существует и не является директорией: {path}")
    elif os.path.exists(out_dir):
        if not _is_writable_directory(out_dir):
            errors.append(f"Директория --out-dir недоступна для записи: {path}")
    else:
        parent = _nearest_existing_parent(out_dir)
        if not parent or not os.path.isdir(parent) or not _is_writable_directory(parent):
            errors.append(f"Родительская директория для --out-dir недоступна для записи: {path}")


def _validate_existing_readable_file(path, name, errors):
    if not os.path.isfile(path):
        errors.append(f"Файл {name} не существует: {path}")
    elif not os.access(path, os.R_OK):
        errors.append(f"Файл {name} не доступен для чтения: {path}")


def _validate_validity_days(value, opt_name, errors):
    try:
        validity = int(value)
        if validity <= 0:
            errors.append(f"{opt_name} обязан быть положительным целым числом.")
    except (TypeError, ValueError):
        errors.append(f"{opt_name} обязан быть целым числом.")


def validate_args(args, logger):
    errors = []

    if not args.subject or not args.subject.strip():
        errors.append("Должен быть указан непустой --subject.")
    else:
        try:
            from .crypto_utils import parse_dn
            parse_dn(args.subject)
        except ValueError as exc:
            errors.append(f"Некорректный --subject: {exc}")

    if args.key_type not in ["rsa", "ecc"]:
        errors.append("--key-type обязан быть 'rsa' или 'ecc'.")

    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append("Для RSA --key-size обязан быть 4096.")

    if args.key_type == "ecc" and args.key_size != 384:
        errors.append("Для ECC --key-size обязан быть 384.")

    _validate_existing_readable_file(args.passphrase_file, "--passphrase-file", errors)
    _validate_validity_days(args.validity_days, "--validity-days", errors)
    _validate_common_out_dir(args.out_dir, errors)

    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def validate_issue_intermediate_args(args, logger):
    errors = []
    for path, name in [
        (args.root_cert, "--root-cert"),
        (args.root_key, "--root-key"),
        (args.root_pass_file, "--root-pass-file"),
        (args.passphrase_file, "--passphrase-file"),
    ]:
        _validate_existing_readable_file(path, name, errors)

    if not args.subject or not args.subject.strip():
        errors.append("Должен быть указан непустой --subject.")
    else:
        try:
            from .crypto_utils import parse_dn
            parse_dn(args.subject)
        except ValueError as exc:
            errors.append(f"Некорректный --subject: {exc}")

    if args.key_type not in ["rsa", "ecc"]:
        errors.append("--key-type обязан быть 'rsa' или 'ecc'.")
    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append("Для RSA --key-size обязан быть 4096.")
    if args.key_type == "ecc" and args.key_size != 384:
        errors.append("Для ECC --key-size обязан быть 384.")
    if args.pathlen < 0:
        errors.append("--pathlen не может быть отрицательным.")
    _validate_validity_days(args.validity_days, "--validity-days", errors)
    _validate_common_out_dir(args.out_dir, errors)

    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def validate_issue_cert_args(args, logger):
    errors = []
    for path, name in [
        (args.ca_cert, "--ca-cert"),
        (args.ca_key, "--ca-key"),
        (args.ca_pass_file, "--ca-pass-file"),
    ]:
        _validate_existing_readable_file(path, name, errors)
    if args.csr:
        _validate_existing_readable_file(args.csr, "--csr", errors)

    if not args.subject or not args.subject.strip():
        errors.append("Должен быть указан непустой --subject.")
    else:
        try:
            from .crypto_utils import parse_dn
            parse_dn(args.subject)
        except ValueError as exc:
            errors.append(f"Некорректный --subject: {exc}")

    try:
        from .templates import parse_san_entries, validate_template_sans
        names = parse_san_entries(args.san or [])
        validate_template_sans(args.template, names)
    except ValueError as exc:
        errors.append(str(exc))

    _validate_validity_days(args.validity_days, "--validity-days", errors)
    _validate_common_out_dir(args.out_dir, errors)

    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def load_passphrase(path):
    with open(path, "rb") as f:
        passphrase = f.read()
    return passphrase.rstrip(b"\r\n")


def _add_key_args(parser):
    parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="Key type")
    parser.add_argument("--key-size", type=int, default=4096, help="4096 for RSA, 384 for ECC")


def main():
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI Utility")
    subparsers = parser.add_subparsers(dest="command")

    ca_parser = subparsers.add_parser("ca", help="Operations with Certificate Authority")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command")

    init_parser = ca_subparsers.add_parser("init", help="Initialize Root CA")
    init_parser.add_argument("--subject", required=True, help="Distinguished Name (e.g., '/CN=My Root CA')")
    _add_key_args(init_parser)
    init_parser.add_argument("--passphrase-file", required=True, help="Path to file containing passphrase")
    init_parser.add_argument("--out-dir", default="./pki", help="Output directory (default: ./pki)")
    init_parser.add_argument("--validity-days", type=int, default=3650, help="Validity period in days (default: 3650)")
    init_parser.add_argument("--log-file", help="Path to log file (default: stderr)")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files without confirmation")

    verify_parser = ca_subparsers.add_parser("verify", help="Verify a CA certificate against itself")
    verify_parser.add_argument("--cert", required=True, help="Path to CA certificate PEM file")
    verify_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    inter_parser = ca_subparsers.add_parser("issue-intermediate", help="Issue Intermediate CA signed by Root CA")
    inter_parser.add_argument("--root-cert", required=True, help="Path to Root CA certificate PEM")
    inter_parser.add_argument("--root-key", required=True, help="Path to Root CA encrypted private key PEM")
    inter_parser.add_argument("--root-pass-file", required=True, help="Path to Root CA passphrase file")
    inter_parser.add_argument("--subject", required=True, help="Intermediate CA Subject DN")
    _add_key_args(inter_parser)
    inter_parser.add_argument("--passphrase-file", required=True, help="Intermediate CA private key passphrase file")
    inter_parser.add_argument("--out-dir", default="./pki", help="PKI output directory")
    inter_parser.add_argument("--validity-days", type=int, default=1825, help="Intermediate validity period")
    inter_parser.add_argument("--pathlen", type=int, default=0, help="Intermediate CA path length constraint")
    inter_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    cert_parser = ca_subparsers.add_parser("issue-cert", help="Issue end-entity certificate from Intermediate CA")
    cert_parser.add_argument("--ca-cert", required=True, help="Path to Intermediate CA certificate PEM")
    cert_parser.add_argument("--ca-key", required=True, help="Path to Intermediate CA encrypted private key PEM")
    cert_parser.add_argument("--ca-pass-file", required=True, help="Path to Intermediate CA passphrase file")
    cert_parser.add_argument("--template", required=True, choices=["server", "client", "code_signing"], help="Certificate template")
    cert_parser.add_argument("--subject", required=True, help="Leaf certificate Subject DN")
    cert_parser.add_argument("--san", action="append", default=[], help="SAN entry: dns:example.com, ip:192.168.1.1, email:a@b, uri:https://...")
    cert_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory for issued cert/key")
    cert_parser.add_argument("--validity-days", type=int, default=365, help="Leaf validity period")
    cert_parser.add_argument("--csr", help="Optional external CSR to sign")
    cert_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    chain_parser = ca_subparsers.add_parser("verify-chain", help="Validate leaf -> intermediate -> root chain")
    chain_parser.add_argument("--root-cert", required=True, help="Root CA certificate PEM")
    chain_parser.add_argument("--intermediate-cert", required=True, help="Intermediate CA certificate PEM")
    chain_parser.add_argument("--cert", required=True, help="Leaf certificate PEM")
    chain_parser.add_argument("--purpose", choices=["server", "client", "code_signing"], help="Optional EKU purpose check")
    chain_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    args = parser.parse_args()

    if args.command == "ca" and args.ca_command == "init":
        from .logger import setup_logger
        logger = setup_logger(args.log_file)
        validate_args(args, logger)

        try:
            args.passphrase_bytes = load_passphrase(args.passphrase_file)
        except OSError as exc:
            logger.error(f"Ошибка чтения файла парольной фразы: {exc}")
            sys.exit(1)

        from .ca import init_ca
        init_ca(args, logger)
        return

    if args.command == "ca" and args.ca_command == "verify":
        from .logger import setup_logger
        from .ca import verify_ca_certificate
        logger = setup_logger(args.log_file)
        ok = verify_ca_certificate(args.cert, logger)
        sys.exit(0 if ok else 1)

    if args.command == "ca" and args.ca_command == "issue-intermediate":
        from .logger import setup_logger
        from .ca import issue_intermediate
        logger = setup_logger(args.log_file)
        validate_issue_intermediate_args(args, logger)
        args.root_passphrase_bytes = load_passphrase(args.root_pass_file)
        args.passphrase_bytes = load_passphrase(args.passphrase_file)
        issue_intermediate(args, logger)
        return

    if args.command == "ca" and args.ca_command == "issue-cert":
        from .logger import setup_logger
        from .ca import issue_cert
        logger = setup_logger(args.log_file)
        validate_issue_cert_args(args, logger)
        args.ca_passphrase_bytes = load_passphrase(args.ca_pass_file)
        issue_cert(args, logger)
        return

    if args.command == "ca" and args.ca_command == "verify-chain":
        from .logger import setup_logger
        from .ca import verify_chain
        logger = setup_logger(args.log_file)
        ok = verify_chain(args, logger)
        sys.exit(0 if ok else 1)

    parser.print_help()
    sys.exit(1)
