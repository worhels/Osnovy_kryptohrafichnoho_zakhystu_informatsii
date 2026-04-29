"""
Лабораторна робота №5
Тема: Режими роботи шифрів та особливості реалізації

Завдання 2: Flipping Cookie (CryptoHack)

Студент: Чугай Євгеній Олександрович
Група: КБ-232

Репозиторій:
https://github.com/worhels/Osnovy_kryptohrafichnoho_zakhystu_informatsii

Опис:
Реалізація CBC bit-flipping атаки.
Мета — змінити значення admin=False на admin=True без знання ключа.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen

# ─── Налаштування ─────────────────────────────────────────────────────────────

BASE_URL = "https://aes.cryptohack.org/flipping_cookie"
BLOCK_SIZE = 16
TIMEOUT = 10

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


def _require_text_field(data: dict[str, object], field_name: str) -> str:
    """Повертає текстове поле з відповіді API."""
    value = data.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"У відповіді відсутнє коректне поле {field_name!r}: {data!r}")
    return value

# ─── API виклики ──────────────────────────────────────────────────────────────

def get_cookie() -> tuple[bytes, bytes]:
    """Отримує ciphertext cookie та IV з сервера."""
    data = _get(f"{BASE_URL}/get_cookie/")

    if "iv" in data:
        ciphertext = _require_hex_field(data, "cookie")
        iv = _require_hex_field(data, "iv")
    else:
        raw_cookie = _require_hex_field(data, "cookie")
        if len(raw_cookie) < 2 * BLOCK_SIZE:
            raise ValueError(f"Отримано cookie недостатньої довжини: {len(raw_cookie)}")
        iv = raw_cookie[:BLOCK_SIZE]
        ciphertext = raw_cookie[BLOCK_SIZE:]

    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV має бути довжини {BLOCK_SIZE}, отримано {len(iv)}")

    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Отримано ciphertext некоректної довжини: {len(ciphertext)}")

    return ciphertext, iv


def check_admin(cookie: bytes, iv: bytes) -> dict[str, object]:
    """Надсилає cookie та IV на перевірку адміністратора."""
    url = f"{BASE_URL}/check_admin/{cookie.hex()}/{iv.hex()}/"
    return _get(url)

# ─── Атака ────────────────────────────────────────────────────────────────────

def forge_admin_iv(iv: bytes) -> bytes:
    """
    Формує новий IV для CBC bit-flipping атаки.

    Початковий plaintext першого блоку містить:
        admin=False;expi

    Потрібно отримати фрагмент:
        admin=True;

    Оскільки у CBC:
        P1 = D(C1) XOR IV

    то зміна IV приводить до контрольованої зміни P1.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV має бути довжини {BLOCK_SIZE}, отримано {len(iv)}")

    original = b"admin=False"
    target = b"admin=True;"
    delta = xor_bytes(original, target)

    modified_iv = bytearray(iv)
    for index, value in enumerate(delta):
        modified_iv[index] ^= value

    return bytes(modified_iv)


def recover_flag() -> str:
    """Отримує cookie, модифікує IV та повертає прапор."""
    ciphertext, iv = get_cookie()
    log.info("Original ciphertext: %s", ciphertext.hex())
    log.info("Original IV:         %s", iv.hex())

    modified_iv = forge_admin_iv(iv)
    log.info("Modified IV:         %s", modified_iv.hex())

    response = check_admin(ciphertext, modified_iv)
    if "flag" in response:
        return _require_text_field(response, "flag")

    if "error" in response:
        error_message = _require_text_field(response, "error")
        raise RuntimeError(f"Сервер не повернув прапор: {error_message}")

    raise RuntimeError(f"Неочікувана відповідь сервера: {response!r}")


def main() -> None:
    try:
        flag = recover_flag()
    except (URLError, RuntimeError, ValueError) as exc:
        log.error("Атака не вдалась: %s", exc)
        sys.exit(1)

    print()
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
