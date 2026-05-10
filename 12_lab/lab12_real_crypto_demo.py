from __future__ import annotations

import os
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


AAD = b"lab12-demo-context"
CHACHA20_POLY1305_NONCE_SIZE = 12
CHACHA20_POLY1305_TAG_SIZE = 16


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Return byte-wise XOR for two equally sized byte strings."""
    if len(left) != len(right):
        raise ValueError("XOR demo requires equal-length byte strings")

    return bytes(a ^ b for a, b in zip(left, right))


def short_hex(data: bytes, length: int = 48) -> str:
    """Return compact hex for terminal-friendly demo output."""
    hex_data = data.hex()
    return hex_data if len(hex_data) <= length else f"{hex_data[:length]}..."


def print_kv(label: str, value: object) -> None:
    print(f"{label:<34} {value}")


def run_demo(title: str, demo: Callable[[], None]) -> None:
    print(f"\n{'=' * 72}")
    print(title)
    print("=" * 72)
    demo()


def verify_signature(
    public_key: Ed25519PublicKey,
    signature: bytes,
    message: bytes,
) -> bool:
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False

    return True


def raw_ed25519_private_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def raw_ed25519_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def encrypted_part(ciphertext_and_tag: bytes) -> bytes:
    return ciphertext_and_tag[:-CHACHA20_POLY1305_TAG_SIZE]


def random_nonce() -> bytes:
    return os.urandom(CHACHA20_POLY1305_NONCE_SIZE)


def demo_private_key_compromise() -> None:
    victim_private_key = Ed25519PrivateKey.generate()
    victim_public_key = victim_private_key.public_key()

    legitimate_message = b"Legitimate system update"
    legitimate_signature = victim_private_key.sign(legitimate_message)

    print_kv("Victim public key", short_hex(raw_ed25519_public_key(victim_public_key)))
    print_kv("Legitimate message", legitimate_message.decode())
    print_kv("Legitimate signature", short_hex(legitimate_signature))
    print_kv(
        "Legitimate verification",
        verify_signature(victim_public_key, legitimate_signature, legitimate_message),
    )

    stolen_private_key_bytes = raw_ed25519_private_key(victim_private_key)
    attacker_private_key = Ed25519PrivateKey.from_private_bytes(stolen_private_key_bytes)

    forged_message = b"Fake attacker command"
    forged_signature = attacker_private_key.sign(forged_message)

    print("\n[ATTACK]")
    print_kv("Stolen private key bytes", short_hex(stolen_private_key_bytes))
    print_kv("Forged message", forged_message.decode())
    print_kv("Forged signature", short_hex(forged_signature))
    print_kv(
        "Victim public key accepts it",
        verify_signature(victim_public_key, forged_signature, forged_message),
    )

    assert verify_signature(victim_public_key, forged_signature, forged_message)
    print("\nResult: a leaked private key lets an attacker sign as the victim.")


def demo_nonce_reuse() -> None:
    key = ChaCha20Poly1305.generate_key()
    aead = ChaCha20Poly1305(key)

    reused_nonce = random_nonce()
    plaintext_1 = b"Attack at dawn. Send 1000 USD."
    plaintext_2 = b"Attack at dusk. Send 9000 USD."

    ciphertext_1 = aead.encrypt(reused_nonce, plaintext_1, AAD)
    ciphertext_2 = aead.encrypt(reused_nonce, plaintext_2, AAD)

    xor_plaintexts = xor_bytes(plaintext_1, plaintext_2)
    xor_ciphertexts = xor_bytes(encrypted_part(ciphertext_1), encrypted_part(ciphertext_2))

    print_kv("Nonce reused", reused_nonce.hex())
    print_kv("Ciphertext 1", short_hex(ciphertext_1))
    print_kv("Ciphertext 2", short_hex(ciphertext_2))
    print_kv("XOR(plaintexts)", short_hex(xor_plaintexts))
    print_kv("XOR(encrypted parts)", short_hex(xor_ciphertexts))
    print_kv("XOR values equal", xor_plaintexts == xor_ciphertexts)

    assert xor_plaintexts == xor_ciphertexts
    print("\nResult: nonce reuse leaks relationships between plaintexts.")


def demo_symmetric_key_leak() -> None:
    server_key = ChaCha20Poly1305.generate_key()
    server_aead = ChaCha20Poly1305(server_key)

    server_nonce = random_nonce()
    secret_data = b"TOP SECRET: admin_token=KB232-SECRET"
    ciphertext = server_aead.encrypt(server_nonce, secret_data, AAD)

    print_kv("Server nonce", server_nonce.hex())
    print_kv("Ciphertext", short_hex(ciphertext))

    leaked_key = bytes(server_key)
    attacker_aead = ChaCha20Poly1305(leaked_key)
    recovered_plaintext = attacker_aead.decrypt(server_nonce, ciphertext, AAD)

    forged_nonce = random_nonce()
    forged_data = b"FORGED DATA: attacker_role=admin"
    forged_ciphertext = attacker_aead.encrypt(forged_nonce, forged_data, AAD)
    server_decrypted_forgery = server_aead.decrypt(forged_nonce, forged_ciphertext, AAD)

    print("\n[ATTACKER]")
    print_kv("Leaked symmetric key", short_hex(leaked_key))
    print_kv("Recovered plaintext", recovered_plaintext.decode())
    print_kv("Forged nonce", forged_nonce.hex())
    print_kv("Forged ciphertext", short_hex(forged_ciphertext))
    print_kv("Server decrypts forged data", server_decrypted_forgery.decode())

    assert recovered_plaintext == secret_data
    assert server_decrypted_forgery == forged_data
    print("\nResult: a leaked symmetric key breaks confidentiality and authenticity.")


def main() -> None:
    print("LAB 12: REAL CRYPTO FAILURE DEMOS")
    print("Educational examples only. Do not copy these attack patterns.")

    run_demo("[1] PRIVATE KEY COMPROMISE: Ed25519 signatures", demo_private_key_compromise)
    run_demo("[2] NONCE REUSE: ChaCha20-Poly1305", demo_nonce_reuse)
    run_demo("[3] SYMMETRIC KEY LEAK: decrypt and forge", demo_symmetric_key_leak)

    print("\n[SUCCESS] Lab 12 real crypto demo completed")


if __name__ == "__main__":
    main()
