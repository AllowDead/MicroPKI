from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _csr_hash_for_key(private_key):
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP384R1):
        return hashes.SHA384()
    return hashes.SHA256()


def generate_intermediate_csr(subject, private_key, pathlen=0):
    """Build a PKCS#10 CSR for an Intermediate CA."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen), critical=True
    )
    return builder.sign(private_key, _csr_hash_for_key(private_key))


def serialize_csr_to_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr_pem(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())


def verify_csr_signature(csr):
    if not csr.is_signature_valid:
        raise ValueError("Подпись CSR некорректна")


def csr_sans(csr):
    """Return SAN GeneralName values from a CSR, or an empty list."""
    try:
        return list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


def load_csr_from_pem_bytes(data: bytes):
    return x509.load_pem_x509_csr(data)
