from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def generate_intermediate_csr(subject, private_key, pathlen=0):
    """Build a PKCS#10 CSR for an Intermediate CA."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen), critical=True
    )
    return builder.sign(private_key, hashes.SHA256())


def serialize_csr_to_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr_pem(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())


def verify_csr_signature(csr):
    if not csr.is_signature_valid:
        raise ValueError("Подпись CSR некорректна")
