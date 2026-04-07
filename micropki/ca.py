import os
import stat
import datetime
from cryptography.hazmat.primitives import serialization


def init_ca(args, logger):
    subject_name = args.subject
    key_type = args.key_type
    key_size = args.key_size
    passphrase = args.passphrase_bytes
    out_dir = args.out_dir
    validity_days = args.validity_days
    force = args.force

    # Импорты внутри функции для избежания циклов
    from .certificates import generate_key, build_ca_certificate, serialize_cert_to_pem
    from .crypto_utils import parse_dn

    # Создание структуры директорий (KEY-4)
    private_dir = os.path.join(out_dir, "private")
    certs_dir = os.path.join(out_dir, "certs")

    try:
        os.makedirs(private_dir, exist_ok=True)
        os.makedirs(certs_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Не удалось создать директории: {e}")
        raise SystemExit(1)

    # Проверка перезаписи (CLI-6)
    key_path = os.path.join(private_dir, "ca.key.pem")
    cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if not force and (os.path.exists(key_path) or os.path.exists(cert_path)):
        logger.error("Файлы УЦ уже существуют. Используйте --force для перезаписи.")
        raise SystemExit(1)

    # 1. Генерация ключа (PKI-1, LOG-2)
    logger.info("Начало генерации закрытого ключа...")
    private_key = generate_key(key_type, key_size)
    logger.info("Успешное завершение генерации закрытого ключа.")

    # 2. Подписание сертификата (PKI-2, LOG-2)
    logger.info("Начало подписания сертификата УЦ...")
    dn = parse_dn(subject_name)
    cert = build_ca_certificate(dn, private_key, validity_days)
    logger.info("Успешное завершение подписания сертификата УЦ.")

    # 3. Сохранение ключа (KEY-1, KEY-2, KEY-3)
    logger.info(f"Сохранение закрытого ключа в {key_path}...")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    with open(key_path, "wb") as f:
        f.write(key_pem)

    # Установка прав
    if os.name != 'nt':
        os.chmod(key_path, 0o600)
        os.chmod(private_dir, 0o700)
    else:
        logger.warning("ОС Windows: невозможно установить строгие права доступа (0o600/0o700) для ключевого файла.")

    # 4. Сохранение сертификата (PKI-4, PKI-5)
    logger.info(f"Сохранение сертификата в {cert_path}...")
    cert_pem = serialize_cert_to_pem(cert)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    # 5. Генерация policy.txt (POL-1)
    logger.info("Генерация policy.txt...")
    policy_path = os.path.join(out_dir, "policy.txt")
    not_before = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    not_after = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    algo_str = f"RSA-{key_size}" if key_type == 'rsa' else "ECC-P384"

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
    with open(policy_path, "w", encoding="utf-8") as f:
        f.write(policy_content)

    logger.info("Инициализация УЦ успешно завершена.")