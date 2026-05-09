from __future__ import annotations

import json
import logging
import sys
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen


BASE_URL = "https://aes.cryptohack.org/flipping_cookie"
BLOCK_SIZE = 16
TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


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


def get_cookie() -> tuple[bytes, bytes]:
    data = get_json("get_cookie")

    if "iv" in data:
        ciphertext = require_hex(data, "cookie")
        iv = require_hex(data, "iv")
    else:
        raw_cookie = require_hex(data, "cookie")
        if len(raw_cookie) < 2 * BLOCK_SIZE:
            raise ValueError(f"Cookie is too short: {len(raw_cookie)}")
        iv = raw_cookie[:BLOCK_SIZE]
        ciphertext = raw_cookie[BLOCK_SIZE:]

    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"Expected {BLOCK_SIZE}-byte IV, got {len(iv)}")

    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"Unexpected ciphertext length: {len(ciphertext)}")

    return ciphertext, iv


def check_admin(cookie: bytes, iv: bytes) -> dict[str, object]:
    return get_json(f"check_admin/{cookie.hex()}/{iv.hex()}")


def forge_admin_iv(iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"Expected {BLOCK_SIZE}-byte IV, got {len(iv)}")

    original = b"admin=False"
    target = b"admin=True;"
    delta = xor_bytes(original, target)
    modified_iv = bytearray(iv)

    for index, value in enumerate(delta):
        modified_iv[index] ^= value

    return bytes(modified_iv)


def recover_flag() -> str:
    ciphertext, iv = get_cookie()
    modified_iv = forge_admin_iv(iv)

    log.info("Original ciphertext: %s", ciphertext.hex())
    log.info("Original IV: %s", iv.hex())
    log.info("Modified IV: %s", modified_iv.hex())

    response = check_admin(ciphertext, modified_iv)

    if "flag" in response:
        return require_text(response, "flag")

    if "error" in response:
        raise RuntimeError(f"Server did not return a flag: {require_text(response, 'error')}")

    raise RuntimeError(f"Unexpected server response: {response!r}")


def main() -> None:
    try:
        flag = recover_flag()
    except (URLError, RuntimeError, ValueError) as exc:
        log.error("Attack failed: %s", exc)
        sys.exit(1)

    print()
    print("FLAG:", flag)


if __name__ == "__main__":
    main()
