from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen


BASE_URL = "https://aes.cryptohack.org/lazy_cbc"
BLOCK_SIZE = 16
TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AttackResult:
    c1: bytes
    key: bytes
    flag: str


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError(f"Different byte lengths: {len(left)} vs {len(right)}")

    return bytes(a ^ b for a, b in zip(left, right))


def get_json(path: str) -> dict[str, object]:
    url = f"{BASE_URL}/{path}/"

    try:
        with urlopen(url, timeout=TIMEOUT) as response:
            data: object = json.load(response)
    except URLError as exc:
        log.error("HTTP request failed: %s", exc)
        raise
    except ValueError as exc:
        raise ValueError("API returned invalid JSON") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")

    return cast(dict[str, object], data)


def require_text(data: dict[str, object], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Missing valid {field_name!r} field: {data!r}")

    return value


def require_hex(data: dict[str, object], field_name: str) -> bytes:
    value = require_text(data, field_name)

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Field {field_name!r} is not valid hex: {value!r}") from exc


def parse_error_plaintext(error_message: str) -> bytes:
    _, separator, decrypted_hex = error_message.partition(": ")
    if not separator or not decrypted_hex:
        raise ValueError(f"Could not find plaintext hex in error: {error_message!r}")

    try:
        return bytes.fromhex(decrypted_hex)
    except ValueError as exc:
        raise ValueError(f"Could not parse plaintext hex from error: {error_message!r}") from exc


def encrypt(plaintext: bytes) -> bytes:
    ciphertext = require_hex(get_json(f"encrypt/{plaintext.hex()}"), "ciphertext")
    if len(ciphertext) < BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Unexpected ciphertext length: {len(ciphertext)}")

    return ciphertext


def receive(ciphertext: bytes) -> dict[str, object]:
    return get_json(f"receive/{ciphertext.hex()}")


def get_flag(key: bytes) -> str:
    plaintext = require_hex(get_json(f"get_flag/{key.hex()}"), "plaintext")
    return plaintext.decode("utf-8")


def recover_key() -> AttackResult:
    ciphertext = encrypt(b"A" * BLOCK_SIZE)
    c1 = ciphertext[:BLOCK_SIZE]
    malicious = c1 + bytes(BLOCK_SIZE) + c1

    log.info("C1: %s", c1.hex())
    log.info("Malicious ciphertext: %s", malicious.hex())

    response = receive(malicious)
    error_message = require_text(response, "error")
    decrypted = parse_error_plaintext(error_message)

    if len(decrypted) < 3 * BLOCK_SIZE:
        raise ValueError(f"Expected at least {3 * BLOCK_SIZE} decrypted bytes, got {len(decrypted)}")

    p1 = decrypted[:BLOCK_SIZE]
    p3 = decrypted[2 * BLOCK_SIZE:3 * BLOCK_SIZE]
    key = xor_bytes(p1, p3)
    flag = get_flag(key)

    log.info("Recovered key: %s", key.hex())

    return AttackResult(c1=c1, key=key, flag=flag)


def main() -> None:
    try:
        result = recover_key()
    except (RuntimeError, ValueError, URLError) as exc:
        log.error("Attack failed: %s", exc)
        sys.exit(1)

    print()
    print("Recovered KEY:", result.key.hex())
    print("FLAG:", result.flag)


if __name__ == "__main__":
    main()
