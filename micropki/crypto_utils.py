import re
from cryptography import x509
from cryptography.x509.oid import NameOID


def parse_dn(dn_string):
    """Parse DN strings in /CN=...,O=... or CN=...,O=... format."""
    dn_string = (dn_string or "").strip()
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
            if len(val) != 2:
                raise ValueError("Атрибут C должен быть двухбуквенным кодом страны")
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, val))
        elif key == 'ST':
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, val))
        elif key == 'L':
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, val))
        elif key in {'EMAIL', 'EMAILADDRESS', 'E'}:
            attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, val))
        elif key == 'OU':
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, val))
        else:
            raise ValueError(f"Неподдерживаемый атрибут DN: '{key}'")

    if not attributes:
        raise ValueError("Пустой Subject DN")

    return x509.Name(attributes)


def name_to_string(name):
    """Return a compact human-readable DN string."""
    oid_to_key = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
        NameOID.EMAIL_ADDRESS: "EMAIL",
    }
    return ",".join(f"{oid_to_key.get(attr.oid, attr.oid._name)}={attr.value}" for attr in name)


def common_name_or_default(name, default="certificate"):
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else default
