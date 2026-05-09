import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"lab9-x25519-hkdf-aesgcm",
    ).derive(shared_secret)


def main() -> None:
    alice_private: x25519.X25519PrivateKey = x25519.X25519PrivateKey.generate()
    bob_private: x25519.X25519PrivateKey = x25519.X25519PrivateKey.generate()

    alice_public: x25519.X25519PublicKey = alice_private.public_key()
    bob_public: x25519.X25519PublicKey = bob_private.public_key()

    alice_shared_secret: bytes = alice_private.exchange(bob_public)
    bob_shared_secret: bytes = bob_private.exchange(alice_public)

    session_key: bytes = derive_session_key(alice_shared_secret)

    nonce: bytes = os.urandom(12)
    aad: bytes = b"lab9-aad"
    plaintext: bytes = b"ECC lab: encrypted message"

    aesgcm = AESGCM(session_key)
    ciphertext: bytes = aesgcm.encrypt(nonce, plaintext, aad)
    decrypted: bytes = aesgcm.decrypt(nonce, ciphertext, aad)

    aad_tamper_rejected: bool = False

    try:
        aesgcm.decrypt(nonce, ciphertext, b"wrong-aad")
    except InvalidTag:
        aad_tamper_rejected = True

    print(f"Shared secrets equal: {alice_shared_secret == bob_shared_secret}")
    print(f"Shared secret preview: {alice_shared_secret.hex()[:64]}...")
    print(f"Session key: {session_key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"AAD: {aad.decode()}")
    print(f"Ciphertext preview: {ciphertext.hex()[:64]}...")
    print(f"AES-GCM decrypt OK: {decrypted == plaintext}")
    print(f"AAD tamper rejected: {aad_tamper_rejected}")


if __name__ == "__main__":
    main()
