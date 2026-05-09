from __future__ import annotations

import os
import sys
from collections.abc import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


SEPARATOR = "=" * 70
AAD = b"lab5-associated-data"


def tamper_ciphertext(ciphertext: bytes) -> bytes:
    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    return bytes(tampered)


def print_block(title: str) -> None:
    print(SEPARATOR)
    print(title)
    print(SEPARATOR)


def verify_tamper_rejection(
    decrypt: Callable[[bytes], bytes],
    tampered_ciphertext: bytes,
) -> bool:
    try:
        decrypt(tampered_ciphertext)
    except InvalidTag:
        print("Tampered decrypt:   InvalidTag")
        return True

    print("Tampered decrypt:   SUCCESS")
    return False


def test_chacha20_poly1305() -> bool:
    print_block("ChaCha20-Poly1305")

    key = ChaCha20Poly1305.generate_key()
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    plaintext = b"Secret message"
    ciphertext = cipher.encrypt(nonce, plaintext, AAD)
    decrypted = cipher.decrypt(nonce, ciphertext, AAD)
    tampered = tamper_ciphertext(ciphertext)

    print("Plaintext:          ", plaintext)
    print("AAD:                ", AAD)
    print("Nonce:              ", nonce.hex())
    print("Ciphertext + tag:   ", ciphertext.hex())
    print("Decrypted:          ", decrypted)
    print("Tampered ciphertext:", tampered.hex())

    return verify_tamper_rejection(
        lambda candidate: cipher.decrypt(nonce, candidate, AAD),
        tampered,
    )


def test_aes_gcm() -> bool:
    print()
    print_block("AES-GCM")

    key = AESGCM.generate_key(bit_length=128)
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = b"Attack at dawn"
    ciphertext = cipher.encrypt(nonce, plaintext, AAD)
    decrypted = cipher.decrypt(nonce, ciphertext, AAD)
    tampered = tamper_ciphertext(ciphertext)

    print("Plaintext:          ", plaintext)
    print("AAD:                ", AAD)
    print("Nonce:              ", nonce.hex())
    print("Ciphertext + tag:   ", ciphertext.hex())
    print("Decrypted:          ", decrypted)
    print("Tampered ciphertext:", tampered.hex())

    return verify_tamper_rejection(
        lambda candidate: cipher.decrypt(nonce, candidate, AAD),
        tampered,
    )


def main() -> None:
    checks = [test_chacha20_poly1305(), test_aes_gcm()]

    print()
    print_block("Conclusion")

    if all(checks):
        print("Both AEAD modes detected ciphertext modification.")
        print("ChaCha20-Poly1305 and AES-GCM provide confidentiality, integrity, and authenticity.")
        return

    print("Unexpected result: modified ciphertext was not rejected.")
    sys.exit(1)


if __name__ == "__main__":
    main()
