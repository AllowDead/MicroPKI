import datetime
import os
import re
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def confirm_overwrite(existing_paths, input_func=input):
    print("Следующие файлы уже существуют и будут перезаписаны:", file=sys.stderr)
    for path in existing_paths:
        print(f"  - {path}", file=sys.stderr)
    try:
        answer = input_func("Перезаписать файлы? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes", "д", "да"}


def _write_private_key_securely(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if os.name != "nt":
        fd = os.open(path, flags, 0o600)
    else:
        fd = os.open(path, flags)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)


def _write_file(path, data, binary=True):
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    with open(path, mode, **kwargs) as f:
        f.write(data)


def _safe_basename_from_subject(subject):
    from .crypto_utils import common_name_or_default
    cn = common_name_or_default(subject, "certificate")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", cn).strip("._")
    return safe or "certificate"


def init_ca(args, logger):
    subject_name = args.subject
    key_type = args.key_type
    key_size = args.key_size
    passphrase = args.passphrase_bytes
    out_dir = os.path.abspath(args.out_dir)
    validity_days = args.validity_days
    force = args.force

    from .certificates import generate_key, build_ca_certificate, serialize_cert_to_pem
    from .crypto_utils import parse_dn

    private_dir = os.path.join(out_dir, "private")
    certs_dir = os.path.join(out_dir, "certs")

    try:
        os.makedirs(private_dir, mode=0o700, exist_ok=True)
        os.makedirs(certs_dir, exist_ok=True)
        if os.name != "nt":
            os.chmod(private_dir, 0o700)
    except OSError as exc:
        logger.error(f"Не удалось создать директории: {exc}")
        raise SystemExit(1)

    key_path = os.path.abspath(os.path.join(private_dir, "ca.key.pem"))
    cert_path = os.path.abspath(os.path.join(certs_dir, "ca.cert.pem"))
    policy_path = os.path.abspath(os.path.join(out_dir, "policy.txt"))

    existing_paths = [path for path in (key_path, cert_path, policy_path) if os.path.exists(path)]
    if existing_paths and not force:
        if not confirm_overwrite(existing_paths):
            logger.error("Перезапись отменена пользователем. Используйте --force для перезаписи без подтверждения.")
            raise SystemExit(1)

    logger.info("Начало генерации закрытого ключа...")
    private_key = generate_key(key_type, key_size)
    logger.info("Успешное завершение генерации закрытого ключа.")

    logger.info("Начало подписания сертификата УЦ...")
    try:
        dn = parse_dn(subject_name)
        cert = build_ca_certificate(dn, private_key, validity_days)
    except ValueError as exc:
        logger.error(f"Ошибка формирования сертификата: {exc}")
        raise SystemExit(1)
    logger.info("Успешное завершение подписания сертификата УЦ.")

    logger.info(f"Сохранение закрытого ключа в {key_path}...")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    try:
        _write_private_key_securely(key_path, key_pem)
    except OSError as exc:
        logger.error(f"Не удалось сохранить закрытый ключ: {exc}")
        raise SystemExit(1)

    if os.name == "nt":
        logger.warning("ОС Windows: невозможно гарантировать POSIX-права 0o600/0o700 для ключевого файла.")

    logger.info(f"Сохранение сертификата в {cert_path}...")
    cert_pem = serialize_cert_to_pem(cert)
    try:
        _write_file(cert_path, cert_pem, binary=True)
    except OSError as exc:
        logger.error(f"Не удалось сохранить сертификат: {exc}")
        raise SystemExit(1)

    logger.info(f"Генерация policy.txt: {policy_path}")
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    algo_str = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"

    policy_content = f"""Политика сертификации УЦ
Версия: 1.0
Дата создания: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

Имя УЦ (Subject DN): {subject_name}
Серийный номер: {hex(cert.serial_number)}
Период действия:
  NotBefore: {not_before}
  NotAfter: {not_after}
Алгоритм и размер ключа: {algo_str}

Описание: Корневой УЦ для демонстрации MicroPKI.
"""
    try:
        _write_file(policy_path, policy_content, binary=False)
    except OSError as exc:
        logger.error(f"Не удалось сохранить policy.txt: {exc}")
        raise SystemExit(1)

    logger.info("Инициализация УЦ успешно завершена.")


def _verify_certificate_signature(cert):
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return
    raise ValueError("Неподдерживаемый тип публичного ключа сертификата")


def verify_ca_certificate(cert_path, logger):
    cert_path = os.path.abspath(cert_path)
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        if cert.subject != cert.issuer:
            raise ValueError("сертификат не является self-issued: Subject не равен Issuer")

        _verify_certificate_signature(cert)

        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise ValueError("сертификат не находится в текущем периоде действия")

        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if not basic_constraints.ca:
            raise ValueError("Basic Constraints не содержит CA=TRUE")

        ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if aki_ext.value.key_identifier != ski_ext.value.digest:
            raise ValueError("AKI не совпадает с SKI")

        logger.info(f"Самопроверка сертификата успешна: {cert_path}")
        print(f"{cert_path}: OK")
        return True
    except Exception as exc:
        logger.error(f"Самопроверка сертификата не пройдена: {exc}")
        print(f"{cert_path}: FAILED", file=sys.stderr)
        return False


def issue_intermediate(args, logger):
    from .certificates import (
        build_intermediate_certificate,
        generate_key,
        load_certificate,
        load_private_key,
        serialize_cert_to_pem,
    )
    from .crypto_utils import name_to_string, parse_dn
    from .csr import generate_intermediate_csr, serialize_csr_to_pem, verify_csr_signature

    out_dir = os.path.abspath(args.out_dir)
    private_dir = os.path.join(out_dir, "private")
    certs_dir = os.path.join(out_dir, "certs")
    csrs_dir = os.path.join(out_dir, "csrs")
    os.makedirs(private_dir, mode=0o700, exist_ok=True)
    os.makedirs(certs_dir, exist_ok=True)
    os.makedirs(csrs_dir, exist_ok=True)
    if os.name != "nt":
        os.chmod(private_dir, 0o700)

    try:
        root_cert = load_certificate(args.root_cert)
        root_key = load_private_key(args.root_key, args.root_passphrase_bytes)
    except Exception as exc:
        logger.error(f"Не удалось загрузить Root CA сертификат или ключ: {exc}")
        raise SystemExit(1)

    try:
        subject = parse_dn(args.subject)
        intermediate_key = generate_key(args.key_type, args.key_size)
        logger.info("Generation of Intermediate CA CSR started.")
        csr = generate_intermediate_csr(subject, intermediate_key, args.pathlen)
        verify_csr_signature(csr)
        logger.info("Generation of Intermediate CA CSR completed.")

        logger.info("Signing of Intermediate CA certificate by Root CA started.")
        cert = build_intermediate_certificate(csr, root_cert, root_key, args.validity_days, args.pathlen)
        logger.info("Signing of Intermediate CA certificate by Root CA completed.")
    except Exception as exc:
        logger.error(f"Ошибка выпуска Intermediate CA: {exc}")
        raise SystemExit(1)

    key_path = os.path.join(private_dir, "intermediate.key.pem")
    cert_path = os.path.join(certs_dir, "intermediate.cert.pem")
    csr_path = os.path.join(csrs_dir, "intermediate.csr.pem")
    policy_path = os.path.join(out_dir, "policy.txt")

    key_pem = intermediate_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(args.passphrase_bytes),
    )
    try:
        _write_private_key_securely(key_path, key_pem)
        _write_file(cert_path, serialize_cert_to_pem(cert), binary=True)
        _write_file(csr_path, serialize_csr_to_pem(csr), binary=True)
    except OSError as exc:
        logger.error(f"Не удалось сохранить файлы Intermediate CA: {exc}")
        raise SystemExit(1)

    algo_str = f"RSA-{args.key_size}" if args.key_type == "rsa" else "ECC-P384"
    section = f"""

--- Intermediate CA ---
Subject DN: {name_to_string(cert.subject)}
Serial Number: {hex(cert.serial_number)}
Validity:
  NotBefore: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}
  NotAfter: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm and Size: {algo_str}
Path Length Constraint: {args.pathlen}
Issuer DN: {name_to_string(root_cert.subject)}
"""
    try:
        with open(policy_path, "a", encoding="utf-8") as f:
            f.write(section)
    except OSError as exc:
        logger.error(f"Не удалось обновить policy.txt: {exc}")
        raise SystemExit(1)

    logger.info(f"Intermediate CA key saved: {os.path.abspath(key_path)}")
    logger.info(f"Intermediate CA certificate saved: {os.path.abspath(cert_path)}")
    logger.info(f"Intermediate CA CSR saved: {os.path.abspath(csr_path)}")
    print(f"Intermediate CA certificate: {cert_path}")
    print(f"Intermediate CA key: {key_path}")


def issue_cert(args, logger):
    from .certificates import (
        build_end_entity_certificate,
        generate_end_entity_key,
        load_certificate,
        load_private_key,
        serialize_cert_to_pem,
    )
    from .crypto_utils import name_to_string, parse_dn
    from .csr import load_csr_pem, verify_csr_signature
    from .templates import parse_san_entries, validate_template_sans

    os.makedirs(args.out_dir, exist_ok=True)
    try:
        ca_cert = load_certificate(args.ca_cert)
        ca_key = load_private_key(args.ca_key, args.ca_passphrase_bytes)
    except Exception as exc:
        logger.error(f"Не удалось загрузить Intermediate CA сертификат или ключ: {exc}")
        raise SystemExit(1)

    try:
        subject = parse_dn(args.subject)
        san_names = parse_san_entries(args.san or [])
        validate_template_sans(args.template, san_names)

        if args.csr:
            csr = load_csr_pem(args.csr)
            verify_csr_signature(csr)
            try:
                bc = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                if bc.ca:
                    logger.warning("CSR requests CA=TRUE; overriding/rejecting for end-entity certificate.")
                    raise ValueError("CSR с CA=TRUE нельзя подписывать как end-entity сертификат")
            except x509.ExtensionNotFound:
                pass
            public_key = csr.public_key()
            private_key = None
        else:
            private_key = generate_end_entity_key("rsa", 2048)
            public_key = private_key.public_key()

        cert = build_end_entity_certificate(
            subject=subject,
            public_key=public_key,
            issuer_cert=ca_cert,
            issuer_private_key=ca_key,
            template=args.template,
            san_names=san_names,
            validity_days=args.validity_days,
        )
    except Exception as exc:
        logger.error(f"Ошибка выпуска конечного сертификата: {exc}")
        raise SystemExit(1)

    base = _safe_basename_from_subject(subject)
    cert_path = os.path.join(args.out_dir, f"{base}.cert.pem")
    key_path = os.path.join(args.out_dir, f"{base}.key.pem")

    try:
        _write_file(cert_path, serialize_cert_to_pem(cert), binary=True)
        if private_key is not None:
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            _write_private_key_securely(key_path, key_pem)
            logger.warning(f"End-entity private key is stored unencrypted: {os.path.abspath(key_path)}")
    except OSError as exc:
        logger.error(f"Не удалось сохранить конечный сертификат или ключ: {exc}")
        raise SystemExit(1)

    san_text = ",".join(args.san or [])
    issued_at = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    logger.info(
        f"Successful issuance of an end-entity certificate: template={args.template}, "
        f"subject={name_to_string(subject)}, SANs={san_text}, serial={hex(cert.serial_number)}, issued_at={issued_at}"
    )
    print(f"Certificate: {cert_path}")
    if private_key is not None:
        print(f"Private key: {key_path}")


def verify_chain(args, logger):
    from .certificates import load_certificate
    from .chain import validate_chain
    try:
        root = load_certificate(args.root_cert)
        intermediate = load_certificate(args.intermediate_cert)
        leaf = load_certificate(args.cert)
        validate_chain(root, intermediate, leaf, args.purpose)
        logger.info("Chain validation successful.")
        print(f"{args.cert}: OK")
        return True
    except Exception as exc:
        logger.error(f"Chain validation failed: {exc}")
        print(f"{args.cert}: FAILED", file=sys.stderr)
        return False
