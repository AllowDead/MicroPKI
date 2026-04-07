import re
from cryptography import x509
from cryptography.x509.oid import NameOID


def parse_dn(dn_string):
    """Парсит строку DN форматов /CN=...,O=... или CN=...,O=..."""
    dn_string = dn_string.strip()
    # Заменяем начальный слеш, если он есть
    if dn_string.startswith('/'):
        dn_string = dn_string[1:]

    parts = [p.strip() for p in re.split(r'[,/]', dn_string) if p.strip()]
    attributes = []

    for part in parts:
        if '=' not in part:
            raise ValueError(f"Некорректный синтаксис DN: отсутствует '=' в части '{part}'")
        key, val = part.split('=', 1)
        key = key.strip().upper()
        val = val.strip()

        if not val:
            raise ValueError(f"Пустое значение в DN для ключа '{key}'")

        if key == 'CN':
            attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, val))
        elif key == 'O':
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, val))
        elif key == 'C':
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, val))
        elif key == 'ST':
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, val))
        elif key == 'L':
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, val))
        else:
            raise ValueError(f"Неподдерживаемый атрибут DN: '{key}'")

    if not attributes:
        raise ValueError("Пустой Subject DN")

    return x509.Name(attributes)