from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
KEY_PATH = OUT_DIR / "server.key"
CSR_PATH = OUT_DIR / "server.csr"

SUBJECT_CN = "localhost"
SAN_DNS = "localhost"
SAN_IP = "127.0.0.1"


def save_private_key(private_key: rsa.RSAPrivateKey) -> None:
    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def load_or_create_key() -> rsa.RSAPrivateKey:
    OUT_DIR.mkdir(exist_ok=True)

    if KEY_PATH.exists() and KEY_PATH.stat().st_size > 0:
        key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)

        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("Expected RSA private key in out/server.key.")

        return cast(rsa.RSAPrivateKey, key)

    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    save_private_key(private_key)
    return private_key


def main() -> None:
    private_key = load_or_create_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Chernihiv"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab10"),
            x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT_CN),
        ]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(SAN_DNS),
                    x509.IPAddress(ipaddress.ip_address(SAN_IP)),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    CSR_PATH.write_bytes(csr_pem)

    san = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value

    print(f"File: {CSR_PATH.relative_to(BASE_DIR)}")
    print(f"Subject: {csr.subject.rfc4514_string()}")
    print(f"SAN: {san}")
    print("Signature algorithm: sha256")
    print(csr_pem.decode().splitlines()[0])


if __name__ == "__main__":
    main()
