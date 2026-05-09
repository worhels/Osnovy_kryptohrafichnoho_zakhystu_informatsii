from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
CERT_PATHS = [
    OUT_DIR / "server_self.crt",
    OUT_DIR / "rootCA.crt",
    OUT_DIR / "server_ca.crt",
]


def print_extension(
    cert: x509.Certificate,
    extension_type: type[x509.ExtensionType],
) -> None:
    try:
        extension = cert.extensions.get_extension_for_class(extension_type)
        print(f"{extension_type.__name__}: {extension.value}")
    except x509.ExtensionNotFound:
        print(f"{extension_type.__name__}: <none>")


def show_certificate(path: Path) -> None:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    public_key = cert.public_key()
    signature_algorithm = cert.signature_hash_algorithm

    print("=" * 80)
    print(f"File: {path.relative_to(BASE_DIR)}")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Validity: {cert.not_valid_before_utc} -> {cert.not_valid_after_utc}")
    print(f"Serial: {cert.serial_number}")
    print(
        "Signature algorithm: "
        f"{signature_algorithm.name if signature_algorithm else 'unknown'}"
    )

    if isinstance(public_key, rsa.RSAPublicKey):
        print(f"Public key: RSA {public_key.key_size} bits")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        print(f"Public key: EC {public_key.curve.name}")
    else:
        print(f"Public key: {type(public_key).__name__}")

    print_extension(cert, x509.SubjectAlternativeName)
    print_extension(cert, x509.BasicConstraints)
    print_extension(cert, x509.KeyUsage)
    print_extension(cert, x509.ExtendedKeyUsage)


def main() -> None:
    for path in CERT_PATHS:
        if path.exists() and path.stat().st_size > 0:
            show_certificate(path)
        else:
            print(f"Missing: {path.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    main()
