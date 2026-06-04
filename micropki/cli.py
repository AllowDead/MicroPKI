import argparse
import os
import socket
import stat
import sys


DEFAULT_DB_PATH = "./pki/micropki.db"


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


def _validate_db_parent(path, errors):
    parent = os.path.dirname(os.path.abspath(path)) or "."
    if os.path.exists(parent):
        if not _is_writable_directory(parent):
            errors.append(f"Директория для --db-path недоступна для записи: {parent}")
    else:
        nearest = _nearest_existing_parent(parent)
        if not nearest or not _is_writable_directory(nearest):
            errors.append(f"Родительская директория для --db-path недоступна для записи: {parent}")


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
    if getattr(args, "db_path", None):
        _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)

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
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)

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
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)

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


def _add_db_path_arg(parser):
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="SQLite database path (default: ./pki/micropki.db)")


def _print_show_cert(db_path, serial, logger):
    from .database import get_certificate_by_serial
    try:
        record = get_certificate_by_serial(db_path, serial)
    except ValueError as exc:
        logger.error(str(exc))
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not record:
        logger.error(f"Certificate not found: serial={serial}")
        print("Certificate not found", file=sys.stderr)
        sys.exit(1)
    logger.info(f"Certificate retrieval via ca show-cert: serial={record['serial_hex']}")
    print(record["cert_pem"], end="")


def _check_repo_status(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, int(port))) == 0


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
    _add_db_path_arg(init_parser)

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
    _add_db_path_arg(inter_parser)

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
    _add_db_path_arg(cert_parser)

    chain_parser = ca_subparsers.add_parser("verify-chain", help="Validate leaf -> intermediate -> root chain")
    chain_parser.add_argument("--root-cert", required=True, help="Root CA certificate PEM")
    chain_parser.add_argument("--intermediate-cert", required=True, help="Intermediate CA certificate PEM")
    chain_parser.add_argument("--cert", required=True, help="Leaf certificate PEM")
    chain_parser.add_argument("--purpose", choices=["server", "client", "code_signing"], help="Optional EKU purpose check")
    chain_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    list_parser = ca_subparsers.add_parser("list-certs", help="List certificates stored in the database")
    list_parser.add_argument("--status", choices=["valid", "revoked", "expired"], help="Filter by certificate status")
    list_parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    _add_db_path_arg(list_parser)
    list_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    show_parser = ca_subparsers.add_parser("show-cert", help="Print a stored certificate PEM by serial")
    show_parser.add_argument("serial", help="Certificate serial number in hexadecimal")
    show_parser.add_argument("--format", choices=["pem"], default="pem", help="Output format")
    _add_db_path_arg(show_parser)
    show_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    db_parser = subparsers.add_parser("db", help="Database operations")
    db_subparsers = db_parser.add_subparsers(dest="db_command")
    db_init_parser = db_subparsers.add_parser("init", help="Initialise the SQLite certificate database")
    _add_db_path_arg(db_init_parser)
    db_init_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    repo_parser = subparsers.add_parser("repo", help="Repository HTTP server operations")
    repo_subparsers = repo_parser.add_subparsers(dest="repo_command")
    serve_parser = repo_subparsers.add_parser("serve", help="Start the certificate repository HTTP server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=8080, help="TCP port")
    _add_db_path_arg(serve_parser)
    serve_parser.add_argument("--cert-dir", default="./pki/certs", help="Directory containing CA PEM certificates")
    serve_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    status_parser = repo_subparsers.add_parser("status", help="Check whether a repository port is accepting TCP connections")
    status_parser.add_argument("--host", default="127.0.0.1", help="Host to check")
    status_parser.add_argument("--port", type=int, default=8080, help="Port to check")

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

    if args.command == "ca" and args.ca_command == "list-certs":
        from .database import format_records, list_certificates
        from .logger import setup_logger
        logger = setup_logger(args.log_file)
        try:
            records = list_certificates(args.db_path, status=args.status)
            print(format_records(records, args.format))
        except Exception as exc:
            logger.error(f"Database query failed: {exc}")
            print(f"Database query failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "ca" and args.ca_command == "show-cert":
        from .logger import setup_logger
        logger = setup_logger(args.log_file)
        _print_show_cert(args.db_path, args.serial, logger)
        return

    if args.command == "db" and args.db_command == "init":
        from .database import init_database
        from .logger import setup_logger
        logger = setup_logger(args.log_file)
        errors = []
        _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
        if errors:
            for err in errors:
                logger.error(err)
            sys.exit(1)
        try:
            db_path = init_database(args.db_path)
            logger.info(f"Database initialisation completed: {db_path}")
            print(f"Database initialised: {db_path}")
        except Exception as exc:
            logger.error(f"Database initialisation failed: {exc}")
            print(f"Database initialisation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "repo" and args.repo_command == "serve":
        from .logger import setup_logger
        from .repository import serve_repository
        logger = setup_logger(args.log_file)
        try:
            serve_repository(args.host, args.port, args.db_path, args.cert_dir, logger)
        except OSError as exc:
            logger.error(f"Repository server failed: {exc}")
            print(f"Repository server failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "repo" and args.repo_command == "status":
        running = _check_repo_status(args.host, args.port)
        print("running" if running else "not running")
        sys.exit(0 if running else 1)

    parser.print_help()
    sys.exit(1)
