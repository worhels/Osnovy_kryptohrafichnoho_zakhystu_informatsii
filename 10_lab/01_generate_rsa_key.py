from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
KEY_PATH = OUT_DIR / "server.key"


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    key_pem: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    KEY_PATH.write_bytes(key_pem)

    print(f"File: {KEY_PATH.relative_to(BASE_DIR)}")
    print("Key type: RSA")
    print(f"Key size: {private_key.key_size} bits")
    print("Public exponent: 65537")
    print("Format: PEM")
    print(key_pem.decode().splitlines()[0])


if __name__ == "__main__":
    main()
