"""
Лабораторна робота №5
Тема: Режими роботи шифрів та особливості реалізації

Завдання 3: Дослідження AEAD: ChaCha20-Poly1305 та AES-GCM

Студент: Чугай Євгеній Олександрович
Група: КБ-232

Репозиторій:
https://github.com/worhels/Osnovy_kryptohrafichnoho_zakhystu_informatsii

Опис:
Експериментальна перевірка властивостей AEAD-режимів.
Показано, що ChaCha20-Poly1305 та AES-GCM забезпечують не лише
конфіденційність, але й контроль цілісності та автентичності даних.
"""

from __future__ import annotations

import sys

try:
    import os
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ImportError as exc:
    print("Помилка: не знайдено бібліотеку 'cryptography'.")
    print("Встановіть її командою: pip install cryptography")
    raise SystemExit(1) from exc


SEPARATOR = "=" * 70


def tamper_ciphertext(ciphertext: bytes) -> bytes:
    """Змінює один біт у ciphertext для перевірки автентичності."""
    if not ciphertext:
        raise ValueError("Ciphertext не може бути порожнім")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    return bytes(tampered)


def print_block(title: str) -> None:
    """Друкує заголовок розділу."""
    print(SEPARATOR)
    print(title)
    print(SEPARATOR)


def test_chacha20_poly1305() -> bool:
    """Виконує AEAD-експеримент для ChaCha20-Poly1305."""
    print_block("ChaCha20-Poly1305")

    key = ChaCha20Poly1305.generate_key()
    cipher = ChaCha20Poly1305(key)

    nonce = os.urandom(12)
    plaintext = b"Secret message"
    aad = b"lab5-associated-data"

    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    decrypted = cipher.decrypt(nonce, ciphertext, aad)

    print("Plaintext:          ", plaintext)
    print("AAD:                ", aad)
    print("Nonce:              ", nonce.hex())
    print("Ciphertext + tag:   ", ciphertext.hex())
    print("Decrypted:          ", decrypted)

    tampered = tamper_ciphertext(ciphertext)
    print("Tampered ciphertext:", tampered.hex())

    try:
        cipher.decrypt(nonce, tampered, aad)
        print("Tampered decrypt:   SUCCESS")
        return False
    except InvalidTag:
        print("Tampered decrypt:   InvalidTag")
        return True


def test_aes_gcm() -> bool:
    """Виконує AEAD-експеримент для AES-GCM."""
    print()
    print_block("AES-GCM")

    key = AESGCM.generate_key(bit_length=128)
    cipher = AESGCM(key)

    nonce = os.urandom(12)
    plaintext = b"Attack at dawn"
    aad = b"lab5-associated-data"

    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    decrypted = cipher.decrypt(nonce, ciphertext, aad)

    print("Plaintext:          ", plaintext)
    print("AAD:                ", aad)
    print("Nonce:              ", nonce.hex())
    print("Ciphertext + tag:   ", ciphertext.hex())
    print("Decrypted:          ", decrypted)

    tampered = tamper_ciphertext(ciphertext)
    print("Tampered ciphertext:", tampered.hex())

    try:
        cipher.decrypt(nonce, tampered, aad)
        print("Tampered decrypt:   SUCCESS")
        return False
    except InvalidTag:
        print("Tampered decrypt:   InvalidTag")
        return True


def main() -> None:
    chacha_ok = test_chacha20_poly1305()
    aes_ok = test_aes_gcm()

    print()
    print_block("Висновок")

    if chacha_ok and aes_ok:
        print("В обох AEAD-режимах модифікація ciphertext була виявлена.")
        print("ChaCha20-Poly1305 та AES-GCM забезпечують конфіденційність,")
        print("цілісність і автентичність даних.")
        return

    print("Експеримент завершився неочікувано: зміну ciphertext не було виявлено.")
    sys.exit(1)


if __name__ == "__main__":
    main()
