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
    else:
        if not args.subject or not args.subject.strip():
            errors.append("Должен быть указан непустой --subject, если не используется --csr.")
        else:
            try:
                from .crypto_utils import parse_dn
                parse_dn(args.subject)
            except ValueError as exc:
                errors.append(f"Некорректный --subject: {exc}")

    try:
        from .templates import parse_san_entries, validate_template_sans
        if not args.csr:
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



def validate_revoke_args(args, logger):
    errors = []
    try:
        from .database import normalize_serial_hex
        normalize_serial_hex(args.serial)
    except ValueError as exc:
        errors.append(str(exc))
    try:
        from .revocation import normalize_reason
        normalize_reason(args.reason)
    except ValueError as exc:
        errors.append(str(exc))
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
    if getattr(args, "crl", None):
        parent = os.path.dirname(os.path.abspath(args.crl)) or "."
        if os.path.exists(parent) and not _is_writable_directory(parent):
            errors.append(f"Директория для --crl недоступна для записи: {parent}")
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def validate_gen_crl_args(args, logger):
    errors = []
    if args.next_update <= 0:
        errors.append("--next-update обязан быть положительным целым числом.")
    _validate_common_out_dir(args.out_dir, errors)
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
    ca_cert, ca_key, _ = _resolve_ca_defaults(args.ca, args.out_dir)
    ca_cert = args.ca_cert or ca_cert
    ca_key = args.ca_key or ca_key
    _validate_existing_readable_file(ca_cert, "--ca-cert", errors)
    _validate_existing_readable_file(ca_key, "--ca-key", errors)
    if not args.ca_pass_file:
        errors.append("--ca-pass-file обязателен для расшифровки CA private key при подписи CRL.")
    else:
        _validate_existing_readable_file(args.ca_pass_file, "--ca-pass-file", errors)
    if args.out_file:
        parent = os.path.dirname(os.path.abspath(args.out_file)) or "."
        if os.path.exists(parent) and not _is_writable_directory(parent):
            errors.append(f"Директория для --out-file недоступна для записи: {parent}")
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def _resolve_ca_defaults(ca, out_dir):
    ca_value = str(ca).strip()
    if ca_value.lower() == "root":
        return (
            os.path.join(out_dir, "certs", "ca.cert.pem"),
            os.path.join(out_dir, "private", "ca.key.pem"),
            "root",
        )
    if ca_value.lower() == "intermediate":
        return (
            os.path.join(out_dir, "certs", "intermediate.cert.pem"),
            os.path.join(out_dir, "private", "intermediate.key.pem"),
            "intermediate",
        )
    return (ca_value, None, os.path.splitext(os.path.basename(ca_value))[0] or "ca")


def validate_issue_ocsp_cert_args(args, logger):
    errors = []
    for path, name in [
        (args.ca_cert, "--ca-cert"),
        (args.ca_key, "--ca-key"),
        (args.ca_pass_file, "--ca-pass-file"),
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
    if args.key_type == "rsa" and args.key_size < 2048:
        errors.append("Для OCSP RSA --key-size должен быть не меньше 2048.")
    if args.key_type == "ecc" and args.key_size < 256:
        errors.append("Для OCSP ECC --key-size должен быть не меньше 256.")
    try:
        from .templates import parse_san_entries, san_types
        names = parse_san_entries(args.san or [])
        unsupported = san_types(names) - {"dns", "uri"}
        if unsupported:
            errors.append("OCSP responder certificate поддерживает только DNS или URI SAN.")
    except ValueError as exc:
        errors.append(str(exc))
    _validate_validity_days(args.validity_days, "--validity-days", errors)
    _validate_common_out_dir(args.out_dir, errors)
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def validate_ocsp_serve_args(args, logger):
    errors = []
    for path, name in [
        (args.responder_cert, "--responder-cert"),
        (args.responder_key, "--responder-key"),
        (args.ca_cert, "--ca-cert"),
    ]:
        _validate_existing_readable_file(path, name, errors)
    _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
    if args.port < 1 or args.port > 65535:
        errors.append("--port должен быть в диапазоне 1..65535")
    if args.cache_ttl <= 0:
        errors.append("--cache-ttl должен быть положительным целым числом")
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)



def validate_client_gen_csr_args(args, logger):
    errors = []
    if not args.subject or not args.subject.strip():
        errors.append("Должен быть указан непустой --subject.")
    else:
        try:
            from .crypto_utils import parse_dn
            parse_dn(args.subject)
        except ValueError as exc:
            errors.append(f"Некорректный --subject: {exc}")
    if args.key_type == "rsa" and args.key_size not in {2048, 4096}:
        errors.append("Для client gen-csr RSA --key-size должен быть 2048 или 4096.")
    if args.key_type == "ecc" and args.key_size not in {256, 384}:
        errors.append("Для client gen-csr ECC --key-size должен быть 256 или 384.")
    try:
        from .templates import parse_san_entries
        parse_san_entries(args.san or [])
    except ValueError as exc:
        errors.append(str(exc))
    for attr in ["out_key", "out_csr"]:
        parent = os.path.dirname(os.path.abspath(getattr(args, attr))) or "."
        if os.path.exists(parent) and not _is_writable_directory(parent):
            errors.append(f"Директория для --{attr.replace('_','-')} недоступна для записи: {parent}")
    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def _parse_validation_time(value):
    if not value:
        return None
    import datetime as _dt
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(text)

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
    parser.add_argument("--config", help="Optional config file (JSON or simple TOML) for audit/rate-limit settings")
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
    cert_parser.add_argument("--subject", help="Leaf certificate Subject DN; ignored when --csr is used")
    cert_parser.add_argument("--san", action="append", default=[], help="SAN entry: dns:example.com, ip:192.168.1.1, email:a@b, uri:https://...")
    cert_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory for issued cert/key")
    cert_parser.add_argument("--validity-days", type=int, default=365, help="Leaf validity period")
    cert_parser.add_argument("--csr", help="Optional external CSR to sign")
    cert_parser.add_argument("--log-file", help="Path to log file (default: stderr)")
    _add_db_path_arg(cert_parser)

    ocsp_cert_parser = ca_subparsers.add_parser("issue-ocsp-cert", help="Issue an OCSP responder signing certificate")
    ocsp_cert_parser.add_argument("--ca-cert", required=True, help="Path to Intermediate CA certificate PEM")
    ocsp_cert_parser.add_argument("--ca-key", required=True, help="Path to Intermediate CA encrypted private key PEM")
    ocsp_cert_parser.add_argument("--ca-pass-file", required=True, help="Path to Intermediate CA passphrase file")
    ocsp_cert_parser.add_argument("--subject", required=True, help="OCSP responder Subject DN")
    ocsp_cert_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa", help="OCSP responder key type")
    ocsp_cert_parser.add_argument("--key-size", type=int, default=2048, help="RSA >=2048 or ECC >=256")
    ocsp_cert_parser.add_argument("--san", action="append", default=[], help="SAN entry for OCSP responder: dns:ocsp.example.com or uri:http://...")
    ocsp_cert_parser.add_argument("--out-dir", default="./pki/certs", help="Output directory for OCSP cert/key")
    ocsp_cert_parser.add_argument("--validity-days", type=int, default=365, help="OCSP responder validity period")
    ocsp_cert_parser.add_argument("--log-file", help="Path to log file (default: stderr)")
    _add_db_path_arg(ocsp_cert_parser)

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

    revoke_parser = ca_subparsers.add_parser("revoke", help="Revoke a certificate by serial number")
    revoke_parser.add_argument("serial", help="Certificate serial number in hexadecimal")
    revoke_parser.add_argument("--reason", default="unspecified", help="Revocation reason code")
    revoke_parser.add_argument("--crl", help="Optional CRL output path to regenerate after revocation")
    revoke_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    revoke_parser.add_argument("--out-dir", default="./pki", help="PKI output directory used for automatic CRL paths")
    revoke_parser.add_argument("--next-update", type=int, default=7, help="CRL nextUpdate interval in days if --crl is used")
    revoke_parser.add_argument("--ca-cert", help="CA certificate PEM used to regenerate CRL")
    revoke_parser.add_argument("--ca-key", help="CA private key PEM used to regenerate CRL")
    revoke_parser.add_argument("--ca-pass-file", help="CA private key passphrase file used to regenerate CRL")
    _add_db_path_arg(revoke_parser)
    revoke_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    compromise_parser = ca_subparsers.add_parser("compromise", help="Simulate private key compromise and revoke certificate")
    compromise_parser.add_argument("--cert", required=True, help="Path to compromised certificate PEM")
    compromise_parser.add_argument("--reason", default="keyCompromise", help="Revocation reason code (default: keyCompromise)")
    compromise_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    compromise_parser.add_argument("--out-dir", default="./pki", help="PKI output directory used for audit/CRL paths")
    compromise_parser.add_argument("--crl", help="Optional emergency CRL output path")
    compromise_parser.add_argument("--next-update", type=int, default=7, help="Emergency CRL nextUpdate interval in days")
    compromise_parser.add_argument("--ca-cert", help="CA certificate PEM used to regenerate emergency CRL")
    compromise_parser.add_argument("--ca-key", help="CA private key PEM used to regenerate emergency CRL")
    compromise_parser.add_argument("--ca-pass-file", help="CA private key passphrase file used to regenerate emergency CRL")
    _add_db_path_arg(compromise_parser)
    compromise_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    gen_crl_parser = ca_subparsers.add_parser("gen-crl", help="Generate a CRL for Root or Intermediate CA")
    gen_crl_parser.add_argument("--ca", required=True, help="root, intermediate, or path to a CA certificate")
    gen_crl_parser.add_argument("--next-update", type=int, default=7, help="Days until next CRL update")
    gen_crl_parser.add_argument("--out-file", help="CRL output path")
    gen_crl_parser.add_argument("--out-dir", default="./pki", help="PKI output directory")
    gen_crl_parser.add_argument("--ca-cert", help="Override CA certificate PEM path")
    gen_crl_parser.add_argument("--ca-key", help="Override CA private key PEM path")
    gen_crl_parser.add_argument("--ca-pass-file", required=True, help="CA private key passphrase file")
    _add_db_path_arg(gen_crl_parser)
    gen_crl_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    check_parser = ca_subparsers.add_parser("check-revoked", help="Check revocation status by serial number")
    check_parser.add_argument("serial", help="Certificate serial number in hexadecimal")
    _add_db_path_arg(check_parser)
    check_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command")
    audit_query_parser = audit_subparsers.add_parser("query", help="Search and display audit log entries")
    audit_query_parser.add_argument("--from", dest="from_ts", help="Start timestamp (ISO 8601)")
    audit_query_parser.add_argument("--to", dest="to_ts", help="End timestamp (ISO 8601)")
    audit_query_parser.add_argument("--level", choices=["INFO", "WARNING", "ERROR", "AUDIT"], help="Log level")
    audit_query_parser.add_argument("--operation", help="Operation filter, e.g. issue, revoke, ca_init")
    audit_query_parser.add_argument("--serial", help="Certificate serial filter")
    audit_query_parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    audit_query_parser.add_argument("--verify", action="store_true", help="Verify audit hash chain before returning results")
    audit_query_parser.add_argument("--log-file", default="./pki/audit/audit.log", help="Audit log path")
    audit_query_parser.add_argument("--chain-file", default="./pki/audit/chain.dat", help="Audit chain path")

    audit_verify_parser = audit_subparsers.add_parser("verify", help="Verify full audit log integrity")
    audit_verify_parser.add_argument("--log-file", default="./pki/audit/audit.log", help="Audit log path")
    audit_verify_parser.add_argument("--chain-file", default="./pki/audit/chain.dat", help="Audit chain path")

    audit_ct_parser = audit_subparsers.add_parser("ct-verify", help="Check whether a certificate is present in the CT simulation log")
    audit_ct_parser.add_argument("--cert", required=True, help="Certificate PEM path")
    audit_ct_parser.add_argument("--ct-log", default="./pki/audit/ct.log", help="CT log path")

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
    serve_parser.add_argument("--crl-dir", default=None, help="Directory containing CRL PEM files (default: sibling ../crl of cert-dir)")
    serve_parser.add_argument("--ca-cert", help="Issuer CA certificate PEM for POST /request-cert")
    serve_parser.add_argument("--ca-key", help="Issuer CA private key PEM for POST /request-cert")
    serve_parser.add_argument("--ca-pass-file", help="Issuer CA passphrase file for POST /request-cert")
    serve_parser.add_argument("--api-key", help="Optional pre-shared key required in X-API-Key for POST /request-cert")
    serve_parser.add_argument("--default-validity-days", type=int, default=365, help="Default validity for certificates issued via API")
    serve_parser.add_argument("--rate-limit", type=float, default=0, help="Requests per second per client IP (0 = disabled)")
    serve_parser.add_argument("--rate-burst", type=int, default=10, help="Rate-limit burst allowance")
    serve_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    status_parser = repo_subparsers.add_parser("status", help="Check whether a repository port is accepting TCP connections")
    status_parser.add_argument("--host", default="127.0.0.1", help="Host to check")
    status_parser.add_argument("--port", type=int, default=8080, help="Port to check")

    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP responder operations")
    ocsp_subparsers = ocsp_parser.add_subparsers(dest="ocsp_command")
    ocsp_serve_parser = ocsp_subparsers.add_parser("serve", help="Start the OCSP responder")
    ocsp_serve_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    ocsp_serve_parser.add_argument("--port", type=int, default=8081, help="TCP port")
    _add_db_path_arg(ocsp_serve_parser)
    ocsp_serve_parser.add_argument("--responder-cert", required=True, help="OCSP signing certificate PEM")
    ocsp_serve_parser.add_argument("--responder-key", required=True, help="OCSP signing private key PEM, unencrypted")
    ocsp_serve_parser.add_argument("--ca-cert", required=True, help="Issuer CA certificate PEM")
    ocsp_serve_parser.add_argument("--cache-ttl", type=int, default=60, help="OCSP response cache TTL / nextUpdate seconds")
    ocsp_serve_parser.add_argument("--rate-limit", type=float, default=0, help="Requests per second per client IP (0 = disabled)")
    ocsp_serve_parser.add_argument("--rate-burst", type=int, default=10, help="Rate-limit burst allowance")
    ocsp_serve_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    client_parser = subparsers.add_parser("client", help="Client-side CSR, validation and revocation tools")
    client_subparsers = client_parser.add_subparsers(dest="client_command")

    gen_csr_parser = client_subparsers.add_parser("gen-csr", help="Generate an end-entity private key and CSR")
    gen_csr_parser.add_argument("--subject", required=True, help="CSR subject DN")
    gen_csr_parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    gen_csr_parser.add_argument("--key-size", type=int, default=2048, help="RSA: 2048/4096; ECC: 256/384")
    gen_csr_parser.add_argument("--san", action="append", default=[], help="SAN entry: dns:example.com, ip:127.0.0.1, email:a@b, uri:https://...")
    gen_csr_parser.add_argument("--out-key", default="./key.pem", help="Output private key PEM")
    gen_csr_parser.add_argument("--out-csr", default="./request.csr.pem", help="Output CSR PEM")
    gen_csr_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    request_cert_parser = client_subparsers.add_parser("request-cert", help="Submit a CSR to repository POST /request-cert")
    request_cert_parser.add_argument("--csr", required=True, help="CSR PEM path")
    request_cert_parser.add_argument("--template", required=True, choices=["server", "client", "code_signing"], help="Certificate template")
    request_cert_parser.add_argument("--ca-url", required=True, help="Repository base URL, e.g. http://localhost:8080")
    request_cert_parser.add_argument("--out-cert", default="./cert.pem", help="Output certificate PEM")
    request_cert_parser.add_argument("--api-key", help="Optional X-API-Key value")
    request_cert_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    validate_parser = client_subparsers.add_parser("validate", help="Validate a certificate chain")
    validate_parser.add_argument("--cert", required=True, help="Leaf certificate PEM")
    validate_parser.add_argument("--untrusted", action="append", default=[], help="Intermediate PEM; can be repeated")
    validate_parser.add_argument("--trusted", default="./pki/certs/ca.cert.pem", help="Trusted Root CA PEM bundle")
    validate_parser.add_argument("--crl", help="Optional CRL file or URL for revocation check")
    validate_parser.add_argument("--ocsp", action="store_true", help="Perform OCSP check when an OCSP URL is available")
    validate_parser.add_argument("--ocsp-url", help="Override OCSP responder URL")
    validate_parser.add_argument("--ca-cert", help="Issuer CA certificate for revocation checks; defaults to first --untrusted")
    validate_parser.add_argument("--mode", choices=["chain", "full"], default="full")
    validate_parser.add_argument("--purpose", choices=["server", "client", "code_signing"], help="Optional EKU purpose check")
    validate_parser.add_argument("--validation-time", help="ISO-8601 validation time, e.g. 2026-01-01T00:00:00Z")
    validate_parser.add_argument("--format", choices=["text", "json"], default="text")
    validate_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    check_status_parser = client_subparsers.add_parser("check-status", help="Check certificate revocation status using OCSP first, CRL fallback")
    check_status_parser.add_argument("--cert", required=True, help="Certificate PEM")
    check_status_parser.add_argument("--ca-cert", required=True, help="Issuer CA certificate PEM")
    check_status_parser.add_argument("--crl", help="CRL file or URL")
    check_status_parser.add_argument("--ocsp-url", help="OCSP responder URL override")
    check_status_parser.add_argument("--log-file", help="Path to log file (default: stderr)")

    args = parser.parse_args()
    try:
        from .config import apply_config
        apply_config(args)
    except Exception as exc:
        print(f"Config loading failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.command == "audit" and args.audit_command == "query":
        from .audit import format_entries, query_entries, verify_log
        if args.verify:
            ok, msg, _ = verify_log(args.log_file, args.chain_file)
            if not ok:
                print(msg, file=sys.stderr)
                sys.exit(2)
        entries = query_entries(
            args.log_file,
            start=args.from_ts,
            end=args.to_ts,
            level=args.level,
            operation=args.operation,
            serial=args.serial,
        )
        print(format_entries(entries, args.format))
        return

    if args.command == "audit" and args.audit_command == "verify":
        from .audit import verify_log
        ok, msg, _ = verify_log(args.log_file, args.chain_file)
        print(msg, file=sys.stdout if ok else sys.stderr)
        sys.exit(0 if ok else 2)

    if args.command == "audit" and args.audit_command == "ct-verify":
        from .transparency import certificate_in_ct_log
        ok = certificate_in_ct_log(args.cert, args.ct_log)
        print("present" if ok else "not found")
        sys.exit(0 if ok else 1)

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

    if args.command == "ca" and args.ca_command == "issue-ocsp-cert":
        from .logger import setup_logger
        from .ca import issue_ocsp_cert
        logger = setup_logger(args.log_file)
        validate_issue_ocsp_cert_args(args, logger)
        args.ca_passphrase_bytes = load_passphrase(args.ca_pass_file)
        issue_ocsp_cert(args, logger)
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

    if args.command == "ca" and args.ca_command == "compromise":
        from .logger import setup_logger
        from .audit import get_audit_logger
        from .compromise import compromise_certificate
        logger = setup_logger(args.log_file)
        errors = []
        _validate_existing_readable_file(args.cert, "--cert", errors)
        _validate_db_parent(getattr(args, "db_path", DEFAULT_DB_PATH), errors)
        if args.ca_cert:
            _validate_existing_readable_file(args.ca_cert, "--ca-cert", errors)
        if args.ca_key:
            _validate_existing_readable_file(args.ca_key, "--ca-key", errors)
        if args.ca_pass_file:
            _validate_existing_readable_file(args.ca_pass_file, "--ca-pass-file", errors)
        if errors:
            for err in errors:
                logger.error(err)
            sys.exit(1)
        audit = get_audit_logger(args.out_dir)
        audit.log_event("private_key_compromise", "started", "Private key compromise simulation started", metadata={"cert": args.cert, "reason": args.reason})
        try:
            result = compromise_certificate(args.db_path, args.cert, args.reason, force=args.force, logger=logger)
            if args.crl:
                if not args.ca_cert or not args.ca_key or not args.ca_pass_file:
                    logger.warning("--crl was supplied but --ca-cert, --ca-key and --ca-pass-file are required to regenerate a signed CRL.")
                else:
                    from .crl import generate_crl
                    generate_crl(args.db_path, args.ca_cert, args.ca_key, load_passphrase(args.ca_pass_file), args.crl, args.next_update, logger)
                    print(f"Emergency CRL: {args.crl}")
            audit.log_event("private_key_compromise", "success", "Private key compromise simulated and certificate revoked", metadata={"serial": result["serial_hex"], "public_key_hash": result["public_key_hash"]})
            print(f"{result['serial_hex']}: revoked keyCompromise")
            print(f"Compromised key hash: {result['public_key_hash']}")
        except Exception as exc:
            audit.log_event("private_key_compromise", "failure", f"Private key compromise simulation failed: {exc}", metadata={"cert": args.cert})
            logger.error(f"Compromise simulation failed: {exc}")
            print(f"Compromise simulation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "ca" and args.ca_command == "revoke":
        from .logger import setup_logger
        from .revocation import revoke_by_serial, normalize_reason
        logger = setup_logger(args.log_file)
        validate_revoke_args(args, logger)
        from .audit import get_audit_logger
        audit = get_audit_logger(args.out_dir)
        audit.log_event("revoke_certificate", "started", "Certificate revocation started", metadata={"serial": args.serial, "reason": args.reason})
        try:
            updated = revoke_by_serial(args.db_path, args.serial, normalize_reason(args.reason), force=args.force, logger=logger)
            if updated is None:
                sys.exit(1)
            audit.log_event("revoke_certificate", "success", "Certificate revoked", metadata={"serial": updated["serial_hex"], "reason": updated.get("revocation_reason")})
            print(f"{updated['serial_hex']}: {updated['status']}")
            if args.crl:
                if not args.ca_cert or not args.ca_key or not args.ca_pass_file:
                    logger.warning("--crl was supplied but --ca-cert, --ca-key and --ca-pass-file are required to regenerate a signed CRL.")
                else:
                    from .crl import generate_crl
                    passphrase = load_passphrase(args.ca_pass_file)
                    generate_crl(args.db_path, args.ca_cert, args.ca_key, passphrase, args.crl, args.next_update, logger)
                    print(f"CRL: {args.crl}")
        except PermissionError as exc:
            audit.log_event("revoke_certificate", "failure", str(exc), metadata={"serial": args.serial})
            logger.error(str(exc))
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        except KeyError as exc:
            audit.log_event("revoke_certificate", "failure", str(exc).strip("'"), metadata={"serial": args.serial})
            print(str(exc).strip("'"), file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            audit.log_event("revoke_certificate", "failure", f"Revocation failed: {exc}", metadata={"serial": args.serial})
            logger.error(f"Revocation failed: {exc}")
            print(f"Revocation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "ca" and args.ca_command == "gen-crl":
        from .logger import setup_logger
        from .crl import generate_crl
        logger = setup_logger(args.log_file)
        validate_gen_crl_args(args, logger)
        from .audit import get_audit_logger
        audit = get_audit_logger(args.out_dir)
        audit.log_event("generate_crl", "started", "CRL generation started", metadata={"ca": args.ca})
        ca_cert, ca_key, ca_name = _resolve_ca_defaults(args.ca, args.out_dir)
        ca_cert = args.ca_cert or ca_cert
        ca_key = args.ca_key or ca_key
        out_file = args.out_file or os.path.join(args.out_dir, "crl", f"{ca_name}.crl.pem")
        try:
            result = generate_crl(args.db_path, ca_cert, ca_key, load_passphrase(args.ca_pass_file), out_file, args.next_update, logger)
            audit.log_event("generate_crl", "success", "CRL generated", metadata={"path": result.path, "crl_number": result.crl_number, "revoked_count": result.revoked_count})
            print(f"CRL: {result.path}")
            print(f"CRL number: {result.crl_number}")
            print(f"Revoked certificates: {result.revoked_count}")
        except Exception as exc:
            audit.log_event("generate_crl", "failure", f"CRL generation failed: {exc}", metadata={"ca": args.ca})
            logger.error(f"CRL generation failed: {exc}")
            print(f"CRL generation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "ca" and args.ca_command == "check-revoked":
        from .database import get_certificate_by_serial
        from .logger import setup_logger
        logger = setup_logger(args.log_file)
        try:
            record = get_certificate_by_serial(args.db_path, args.serial)
        except ValueError as exc:
            logger.error(str(exc))
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if not record:
            logger.error(f"Certificate not found: serial={args.serial}")
            print("Certificate not found", file=sys.stderr)
            sys.exit(1)
        print(record["status"])
        sys.exit(0 if record["status"] == "revoked" else 1)

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
            serve_repository(
                args.host, args.port, args.db_path, args.cert_dir, logger, args.crl_dir,
                ca_cert_path=args.ca_cert, ca_key_path=args.ca_key, ca_pass_file=args.ca_pass_file,
                api_key=args.api_key, default_validity_days=args.default_validity_days,
                rate_limit=args.rate_limit, rate_burst=args.rate_burst,
            )
        except OSError as exc:
            logger.error(f"Repository server failed: {exc}")
            print(f"Repository server failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "repo" and args.repo_command == "status":
        running = _check_repo_status(args.host, args.port)
        print("running" if running else "not running")
        sys.exit(0 if running else 1)

    if args.command == "ocsp" and args.ocsp_command == "serve":
        from .logger import setup_logger
        from .ocsp_responder import serve_ocsp
        logger = setup_logger(args.log_file)
        validate_ocsp_serve_args(args, logger)
        try:
            serve_ocsp(
                args.host,
                args.port,
                args.db_path,
                args.responder_cert,
                args.responder_key,
                args.ca_cert,
                args.cache_ttl,
                logger,
                rate_limit=args.rate_limit,
                rate_burst=args.rate_burst,
            )
        except OSError as exc:
            logger.error(f"OCSP responder failed: {exc}")
            print(f"OCSP responder failed: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            logger.error(f"OCSP responder failed: {exc}")
            print(f"OCSP responder failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "client" and args.client_command == "gen-csr":
        from .logger import setup_logger
        from .client import generate_csr
        logger = setup_logger(args.log_file)
        validate_client_gen_csr_args(args, logger)
        try:
            key_path, csr_path = generate_csr(args.subject, args.key_type, args.key_size, args.san, args.out_key, args.out_csr, logger)
            print(f"Private key: {key_path}")
            print(f"CSR: {csr_path}")
        except Exception as exc:
            logger.error(f"CSR generation failed: {exc}")
            print(f"CSR generation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "client" and args.client_command == "request-cert":
        from .logger import setup_logger
        from .client import request_certificate
        logger = setup_logger(args.log_file)
        _validate_existing_readable_file(args.csr, "--csr", [])
        try:
            out = request_certificate(args.csr, args.template, args.ca_url, args.out_cert, args.api_key, logger)
            print(f"Certificate: {out}")
        except Exception as exc:
            logger.error(str(exc))
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "client" and args.client_command == "validate":
        from .logger import setup_logger
        from .client import validate_certificate_chain, check_certificate_status, format_validation_result
        logger = setup_logger(args.log_file)
        try:
            result = validate_certificate_chain(args.cert, args.untrusted, args.trusted, args.purpose, _parse_validation_time(args.validation_time))
            print(format_validation_result(result, args.format))
            if result.ok and args.mode == "full":
                ca_cert = args.ca_cert or (args.untrusted[0] if args.untrusted else None)
                if ca_cert and (args.crl or args.ocsp or args.ocsp_url):
                    status = check_certificate_status(args.cert, ca_cert, crl=args.crl, ocsp_url=args.ocsp_url, logger=logger)
                    print(f"Revocation status: {status.status} via {status.source}")
                    if status.status == "revoked":
                        sys.exit(1)
                    if status.status == "unknown" and args.mode == "full":
                        sys.exit(1)
            sys.exit(0 if result.ok else 1)
        except Exception as exc:
            logger.error(f"Validation failed: {exc}")
            print(f"Validation failed: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.command == "client" and args.client_command == "check-status":
        from .logger import setup_logger
        from .client import check_certificate_status
        logger = setup_logger(args.log_file)
        try:
            status = check_certificate_status(args.cert, args.ca_cert, crl=args.crl, ocsp_url=args.ocsp_url, logger=logger)
            print(f"{status.status} via {status.source}")
            if status.reason:
                print(f"Reason: {status.reason}")
            if status.revocation_time:
                print(f"Revocation time: {status.revocation_time}")
            if status.detail:
                print(status.detail)
            sys.exit(0 if status.status == "good" else 1 if status.status == "revoked" else 2)
        except Exception as exc:
            logger.error(f"Status check failed: {exc}")
            print(f"Status check failed: {exc}", file=sys.stderr)
            sys.exit(2)
        return

    parser.print_help()
    sys.exit(1)
