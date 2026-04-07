import argparse
import os
import sys


def validate_args(args, logger):
    errors = []

    if not args.subject or not args.subject.strip():
        errors.append("Должен быть указан непустой --subject.")

    if args.key_type not in ['rsa', 'ecc']:
        errors.append("--key-type обязан быть 'rsa' или 'ecc'.")

    if args.key_type == 'rsa' and args.key_size != 4096:
        errors.append("Для RSA --key-size обязан быть 4096.")

    if args.key_type == 'ecc' and args.key_size != 384:
        errors.append("Для ECC --key-size обязан быть 384.")

    if not os.path.isfile(args.passphrase_file):
        errors.append(f"Файл --passphrase-file не существует: {args.passphrase_file}")
    elif not os.access(args.passphrase_file, os.R_OK):
        errors.append(f"Файл --passphrase-file не доступен для чтения: {args.passphrase_file}")

    try:
        validity = int(args.validity_days)
        if validity <= 0:
            errors.append("--validity-days обязан быть положительным целым числом.")
    except ValueError:
        errors.append("--validity-days обязан быть целым числом.")

    # Проверка out-dir (создаем, если нет, проверяем запись)
    if os.path.exists(args.out_dir) and not os.path.isdir(args.out_dir):
        errors.append(f"--out-dir существует и не является директорией: {args.out_dir}")
    elif os.path.exists(args.out_dir) and not os.access(args.out_dir, os.W_OK):
        errors.append(f"Директория --out-dir недоступна для записи: {args.out_dir}")

    if errors:
        for err in errors:
            logger.error(err)
        sys.exit(1)


def load_passphrase(path):
    with open(path, "rb") as f:
        passphrase = f.read()
    # Отбрасываем завершающий символ новой строки
    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
    if passphrase.endswith(b'\r'):
        passphrase = passphrase[:-1]
    return passphrase


def main():
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI Utility")
    subparsers = parser.add_subparsers(dest="command")

    # Subкоманда 'ca'
    ca_parser = subparsers.add_parser("ca", help="Operations with Certificate Authority")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command")

    # Subкоманда 'ca init'
    init_parser = ca_subparsers.add_parser("init", help="Initialize Root CA")

    init_parser.add_argument("--subject", required=True, help="Distinguished Name (e.g., '/CN=My Root CA')")
    init_parser.add_argument("--key-type", choices=['rsa', 'ecc'], default="rsa", help="Key type (default: rsa)")
    init_parser.add_argument("--key-size", type=int, default=4096, help="Key size: 4096 for RSA, 384 for ECC")
    init_parser.add_argument("--passphrase-file", required=True, help="Path to file containing passphrase")
    init_parser.add_argument("--out-dir", default="./pki", help="Output directory (default: ./pki)")
    init_parser.add_argument("--validity-days", type=int, default=3650, help="Validity period in days (default: 3650)")
    init_parser.add_argument("--log-file", help="Path to log file (default: stderr)")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files")

    args = parser.parse_args()

    if args.command == "ca" and args.ca_command == "init":
        from .logger import setup_logger
        logger = setup_logger(args.log_file)

        validate_args(args, logger)

        # Безопасная загрузка парольной фразы
        try:
            args.passphrase_bytes = load_passphrase(args.passphrase_file)
        except Exception as e:
            logger.error(f"Ошибка чтения файла парольной фразы: {e}")
            sys.exit(1)

        from .ca import init_ca
        init_ca(args, logger)
    else:
        parser.print_help()