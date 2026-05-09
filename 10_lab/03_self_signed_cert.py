from __future__ import annotations

import datetime
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
KEY_PATH = OUT_DIR / "server.key"
CSR_PATH = OUT_DIR / "server.csr"
CERT_PATH = OUT_DIR / "server_self.crt"

DAYS_VALID = 30


def require_file(path: Path, producer: str) -> None:
    if not path.exists() or path.stat().st_size == 0:
        raise FileNotFoundError(f"Missing {path}. Run {producer} first.")


def load_key() -> rsa.RSAPrivateKey:
    require_file(KEY_PATH, "01_generate_rsa_key.py")
    key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)

    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected RSA private key in out/server.key.")

    return cast(rsa.RSAPrivateKey, key)


def load_csr() -> x509.CertificateSigningRequest:
    require_file(CSR_PATH, "02_generate_csr.py")
    return x509.load_pem_x509_csr(CSR_PATH.read_bytes())


def main() -> None:
    private_key = load_key()
    csr = load_csr()

    now = datetime.datetime.now(datetime.UTC)
    san = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=DAYS_VALID))
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
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"File: {CERT_PATH.relative_to(BASE_DIR)}")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Validity: {cert.not_valid_before_utc} -> {cert.not_valid_after_utc}")
    print(f"SAN: {san}")
    print("BasicConstraints: ca=False")
    print("KeyUsage: digitalSignature, keyEncipherment")
    print("ExtendedKeyUsage: serverAuth")


if __name__ == "__main__":
    main()
