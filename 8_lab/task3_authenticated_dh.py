from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


p = 23
g = 5

a = 6
b = 15

A = pow(g, a, p)
B = pow(g, b, p)

message = f"DH|{A}|{B}".encode("ascii")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

with open("task3_private_key.pem", "wb") as file:
    file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("task3_public_key.pem", "wb") as file:
    file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

with open("task3_signature.bin", "wb") as file:
    file.write(signature)


def verify_signature(data: bytes, sign: bytes) -> bool:
    try:
        public_key.verify(
            sign,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


valid_original = verify_signature(message, signature)

tampered_message = f"DH|{A}|3".encode("ascii")
valid_tampered = verify_signature(tampered_message, signature)

print("=== Task 3. Authenticated Diffie-Hellman with RSA-PSS ===")
print(f"p = {p}")
print(f"g = {g}")
print(f"Public key A = {A}")
print(f"Public key B = {B}")
print()
print(f"Signed message: {message.decode('ascii')}")
print("RSA key size: 2048 bits")
print("Signature algorithm: RSA-PSS")
print("Hash algorithm: SHA-256")
print(f"Signature length: {len(signature)} bytes")
print()
print(f"Original signature verification: {valid_original}")
print()
print("MITM substitution test:")
print(f"Tampered message: {tampered_message.decode('ascii')}")
print(f"Tampered signature verification: {valid_tampered}")
print()
print("Result:")
print("Original DH parameters are authenticated.")
print("If attacker changes A or B, RSA-PSS verification fails.")