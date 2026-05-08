from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Final

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type


SCRYPT_N: Final[int] = 2**14
SCRYPT_R: Final[int] = 8
SCRYPT_P: Final[int] = 1
SCRYPT_DKLEN: Final[int] = 64
PEPPER_SECRET: Final[str] = os.getenv("PEPPER_SECRET", "")

SUPPORTED_ALGORITHMS: Final[tuple[str, ...]] = (
    "bcrypt",
    "scrypt",
    "argon2id",
)

DEFAULT_ALGORITHM: Final[str] = "argon2id"

ALGORITHM_DISPLAY_NAMES: Final[dict[str, str]] = {
    "bcrypt": "bcrypt",
    "scrypt": "scrypt",
    "argon2id": "Argon2id",
}

ARGON2ID_HASHER: Final[PasswordHasher] = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def apply_pepper(password: str) -> str:
    return f"{password}{PEPPER_SECRET}"


def format_algorithm_name(algorithm: str) -> str:
    return ALGORITHM_DISPLAY_NAMES.get(algorithm, algorithm)


def hash_password(password: str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    prepared_password = apply_pepper(password)
    password_bytes = prepared_password.encode("utf-8")

    if algorithm == "bcrypt":
        return bcrypt.hashpw(
            password_bytes,
            bcrypt.gensalt(rounds=12),
        ).decode("utf-8")

    if algorithm == "scrypt":
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password_bytes,
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
            maxmem=_get_scrypt_maxmem(SCRYPT_N, SCRYPT_R, SCRYPT_P),
        )
        return (
            "scrypt$"
            f"n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P},dklen={SCRYPT_DKLEN}$"
            f"{salt.hex()}$"
            f"{digest.hex()}"
        )

    return ARGON2ID_HASHER.hash(prepared_password)


def verify_password(password: str, stored_hash: str) -> bool:
    prepared_password = apply_pepper(password)
    password_bytes = prepared_password.encode("utf-8")

    try:
        if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(password_bytes, stored_hash.encode("utf-8"))

        if stored_hash.startswith("scrypt$"):
            _, parameters, salt_hex, expected_hex = stored_hash.split("$")
            parsed_parameters = _parse_scrypt_parameters(parameters)
            derived = hashlib.scrypt(
                password_bytes,
                salt=bytes.fromhex(salt_hex),
                n=parsed_parameters["n"],
                r=parsed_parameters["r"],
                p=parsed_parameters["p"],
                dklen=parsed_parameters["dklen"],
                maxmem=_get_scrypt_maxmem(
                    parsed_parameters["n"],
                    parsed_parameters["r"],
                    parsed_parameters["p"],
                ),
            )
            return hmac.compare_digest(derived.hex(), expected_hex)

        if stored_hash.startswith("$argon2id$"):
            return ARGON2ID_HASHER.verify(stored_hash, prepared_password)
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError, ValueError, TypeError):
        return False

    return False


def get_algorithm_choices() -> list[tuple[str, str]]:
    return [
        ("argon2id", "Argon2id - рекомендований варіант"),
        ("bcrypt", "bcrypt - сумісний і поширений варіант"),
        ("scrypt", "scrypt - пам'яттєво-складний варіант"),
    ]


def _parse_scrypt_parameters(parameter_block: str) -> dict[str, int]:
    parsed_parameters: dict[str, int] = {}

    for item in parameter_block.split(","):
        key, value = item.split("=", 1)
        parsed_parameters[key] = int(value)

    required_keys = {"n", "r", "p", "dklen"}
    if set(parsed_parameters) != required_keys:
        raise ValueError("Invalid scrypt parameter block")

    return parsed_parameters


def _get_scrypt_maxmem(n: int, r: int, p: int) -> int:
    return max(128 * n * r * p * 2, 64 * 1024 * 1024)
