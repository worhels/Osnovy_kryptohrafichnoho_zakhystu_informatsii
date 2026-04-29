"""
Лабораторна робота №5
Тема: Режими роботи шифрів та особливості реалізації

Завдання 1: Lazy CBC (CryptoHack)

Студент: Чугай Євгеній Олександрович
Група: КБ-232

Репозиторій:
https://github.com/worhels/Osnovy_kryptohrafichnoho_zakhystu_informatsii

Опис:
Реалізація атаки на AES-CBC при умові IV = KEY.
Використано властивість CBC:
KEY = P1 XOR P3
"""

from __future__ import annotations

import logging
import json
import sys
from dataclasses import dataclass
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen

# ─── Налаштування ─────────────────────────────────────────────────────────────

BASE_URL   = "https://aes.cryptohack.org/lazy_cbc"
BLOCK_SIZE = 16
TIMEOUT    = 10

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
log = logging.getLogger(__name__)

# ─── Допоміжні функції ────────────────────────────────────────────────────────

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR двох рядків байт однакової довжини."""
    if len(a) != len(b):
        raise ValueError(f"Різна довжина: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def _get(url: str) -> dict[str, object]:
    """GET-запит до API, повертає JSON або кидає виняток."""
    try:
        with urlopen(url, timeout=TIMEOUT) as response:
            data: object = json.load(response)
    except URLError as exc:
        log.error("HTTP запит не вдався: %s", exc)
        raise
    except ValueError as exc:
        log.error("Сервер повернув некоректний JSON: %s", exc)
        raise ValueError("Некоректна JSON-відповідь від API") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Очікувався JSON-об'єкт, отримано {type(data).__name__}")

    return cast(dict[str, object], data)


def _require_hex_field(data: dict[str, object], field_name: str) -> bytes:
    """Повертає байти з hex-поля відповіді API."""
    value = data.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"У відповіді відсутнє коректне поле {field_name!r}: {data!r}")

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Поле {field_name!r} містить некоректний hex: {value!r}") from exc


def _parse_error_plaintext(error_message: str) -> bytes:
    """Виділяє plaintext у hex-форматі з тексту помилки API."""
    _, separator, decrypted_hex = error_message.partition(": ")
    if not separator or not decrypted_hex:
        raise ValueError(f"Не вдалось знайти hex-дані у помилці: {error_message!r}")

    try:
        return bytes.fromhex(decrypted_hex)
    except ValueError as exc:
        raise ValueError(f"Не вдалось розібрати hex з помилки: {error_message!r}") from exc

# ─── API виклики ──────────────────────────────────────────────────────────────

def encrypt(plaintext: bytes) -> bytes:
    """Шифрує plaintext через API, повертає ciphertext."""
    ciphertext = _require_hex_field(_get(f"{BASE_URL}/encrypt/{plaintext.hex()}/"), "ciphertext")
    if len(ciphertext) < BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Отримано ciphertext некоректної довжини: {len(ciphertext)}")
    return ciphertext


def receive(ciphertext: bytes) -> dict[str, object]:
    """Надсилає ciphertext на /receive, повертає JSON-відповідь."""
    return _get(f"{BASE_URL}/receive/{ciphertext.hex()}/")


def get_flag(key: bytes) -> str:
    """Отримує прапор за допомогою відновленого ключа."""
    plaintext = _require_hex_field(_get(f"{BASE_URL}/get_flag/{key.hex()}/"), "plaintext")
    return plaintext.decode("utf-8")

# ─── Атака ────────────────────────────────────────────────────────────────────

# Формуємо спеціальний шифртекст:
# C = C1 || 0...0 || C1
#
# При дешифруванні:
# P1 = D(C1) XOR KEY
# P3 = D(C1)
#
# => KEY = P1 XOR P3

@dataclass
class AttackResult:
    c1:   bytes
    key:  bytes
    flag: str


def recover_key() -> AttackResult:
    """Відновлює KEY через CBC key-as-IV атаку."""

    # Крок 1: Отримуємо C1
    ciphertext = encrypt(b"A" * BLOCK_SIZE)
    c1 = ciphertext[:BLOCK_SIZE]
    log.info("C1: %s", c1.hex())

    # Крок 2: Формуємо модифікований ciphertext
    malicious = c1 + b"\x00" * BLOCK_SIZE + c1
    log.info("Надсилаємо: %s", malicious.hex())

    # Крок 3: Отримуємо plaintext з помилки
    response = receive(malicious)

    if "error" not in response:
        raise RuntimeError(f"Очікувалось поле 'error', отримано: {list(response.keys())}")

    error_message = response["error"]
    if not isinstance(error_message, str):
        raise ValueError(f"Поле 'error' має некоректний тип: {type(error_message).__name__}")

    decrypted = _parse_error_plaintext(error_message)

    if len(decrypted) < 3 * BLOCK_SIZE:
        raise ValueError(f"Недостатня довжина: очікувалось >={3 * BLOCK_SIZE}, отримано {len(decrypted)}")

    # Крок 4: Відновлюємо ключ
    p1  = decrypted[:BLOCK_SIZE]
    p3  = decrypted[2 * BLOCK_SIZE: 3 * BLOCK_SIZE]
    key = xor_bytes(p1, p3)
    log.info("Відновлений KEY: %s", key.hex())

    # Крок 5: Отримуємо FLAG
    flag = get_flag(key)

    return AttackResult(c1=c1, key=key, flag=flag)

# ─── Точка входу ──────────────────────────────────────────────────────────────

def main() -> None:
    try:
        result = recover_key()
    except (RuntimeError, ValueError, URLError) as exc:
        log.error("Атака не вдалась: %s", exc)
        sys.exit(1)

    print()
    print("Recovered KEY:", result.key.hex())
    print("FLAG:", result.flag)


if __name__ == "__main__":
    main()
