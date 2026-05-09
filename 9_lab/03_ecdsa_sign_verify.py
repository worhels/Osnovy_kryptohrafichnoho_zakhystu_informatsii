from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    signature: bytes,
    message: bytes,
) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def main() -> None:
    private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256K1())
    public_key: ec.EllipticCurvePublicKey = private_key.public_key()

    message = b"Lab 9: ECDSA integrity check"
    tampered_message = b"Lab 9: ECDSA integrity check!"

    signature: bytes = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    public_pem: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    original_ok: bool = verify_signature(public_key, signature, message)
    tampered_ok: bool = verify_signature(public_key, signature, tampered_message)
    public_pem_lines = public_pem.decode().splitlines()

    print("Curve: secp256k1")
    print(f"Message: {message.decode()}")
    print(f"Signature length: {len(signature)} bytes")
    print(f"Signature preview: {signature.hex()[:64]}...")
    print(f"Original message verification: {original_ok}")
    print(f"Tampered message verification: {tampered_ok}")
    print(public_pem_lines[0])
    print(public_pem_lines[-1])


if __name__ == "__main__":
    main()
