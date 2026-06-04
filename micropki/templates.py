import ipaddress
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

SUPPORTED_TEMPLATES = {"server", "client", "code_signing"}
SUPPORTED_SAN_TYPES = {"dns", "ip", "email", "uri"}


def parse_san_entries(entries):
    """Parse CLI SAN entries like dns:example.com into cryptography GeneralName objects."""
    result = []
    for raw in entries or []:
        if ":" not in raw:
            raise ValueError(f"SAN должен иметь формат type:value: {raw}")
        san_type, value = raw.split(":", 1)
        san_type = san_type.strip().lower()
        value = value.strip()
        if san_type not in SUPPORTED_SAN_TYPES:
            raise ValueError(f"Неподдерживаемый тип SAN: {san_type}")
        if not value:
            raise ValueError("Значение SAN не может быть пустым")
        if san_type == "dns":
            result.append(x509.DNSName(value))
        elif san_type == "ip":
            try:
                result.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError as exc:
                raise ValueError(f"Некорректный IP SAN: {value}") from exc
        elif san_type == "email":
            if "@" not in value:
                raise ValueError(f"Некорректный email SAN: {value}")
            result.append(x509.RFC822Name(value))
        elif san_type == "uri":
            parsed = urlparse(value)
            if not parsed.scheme:
                raise ValueError(f"URI SAN должен содержать схему: {value}")
            result.append(x509.UniformResourceIdentifier(value))
    return result


def san_types(general_names):
    types = set()
    for item in general_names or []:
        if isinstance(item, x509.DNSName):
            types.add("dns")
        elif isinstance(item, x509.IPAddress):
            types.add("ip")
        elif isinstance(item, x509.RFC822Name):
            types.add("email")
        elif isinstance(item, x509.UniformResourceIdentifier):
            types.add("uri")
    return types


def validate_template_sans(template, general_names):
    if template not in SUPPORTED_TEMPLATES:
        raise ValueError(f"Неподдерживаемый шаблон сертификата: {template}")

    types = san_types(general_names)
    if template == "server":
        unsupported = types - {"dns", "ip"}
        if unsupported:
            raise ValueError("Server certificate поддерживает только DNS и IP SAN")
        if not types.intersection({"dns", "ip"}):
            raise ValueError("Для server-сертификата нужен хотя бы один DNS или IP SAN")
    elif template == "client":
        unsupported = types - {"email", "dns"}
        if unsupported:
            raise ValueError("Client certificate поддерживает только email и DNS SAN")
    elif template == "code_signing":
        unsupported = types - {"dns", "uri"}
        if unsupported:
            raise ValueError("Code signing certificate поддерживает только DNS или URI SAN")


def eku_for_template(template):
    if template == "server":
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    if template == "client":
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    if template == "code_signing":
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
    raise ValueError(f"Неподдерживаемый шаблон сертификата: {template}")
