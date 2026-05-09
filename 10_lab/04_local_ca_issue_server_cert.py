from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
CSR_PATH = OUT_DIR / "server.csr"
ROOT_KEY_PATH = OUT_DIR / "rootCA.key"
ROOT_CERT_PATH = OUT_DIR / "rootCA.crt"
SERVER_CERT_PATH = OUT_DIR / "server_ca.crt"

DAYS_CA = 365
DAYS_SERVER = 30


def require_file(path: Path, producer: str) -> None:
    if not path.exists() or path.stat().st_size == 0:
        raise FileNotFoundError(f"Missing {path}. Run {producer} first.")


def write_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    print(f"File: {path.relative_to(BASE_DIR)}")


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    require_file(CSR_PATH, "02_generate_csr.py")

    now = datetime.datetime.now(datetime.UTC)

    ca_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LabCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Lab Root CA"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=DAYS_CA))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    write_file(
        ROOT_KEY_PATH,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_file(ROOT_CERT_PATH, ca_cert.public_bytes(serialization.Encoding.PEM))

    csr = x509.load_pem_x509_csr(CSR_PATH.read_bytes())
    san = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=DAYS_SERVER))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    write_file(SERVER_CERT_PATH, server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"Root Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"Server Subject: {server_cert.subject.rfc4514_string()}")
    print(f"Server Issuer: {server_cert.issuer.rfc4514_string()}")
    print("Root BasicConstraints: ca=True")
    print("Server BasicConstraints: ca=False")
    print("Server ExtendedKeyUsage: serverAuth")


if __name__ == "__main__":
    main()
