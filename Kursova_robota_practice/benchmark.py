from __future__ import annotations

import csv
import hashlib
import secrets
import statistics
import time
from pathlib import Path
from typing import Any, Final

import bcrypt
from argon2 import PasswordHasher
from argon2.low_level import Type

from password_hashing import DEFAULT_ALGORITHM, apply_pepper, verify_password


BASE_DIR = Path(__file__).resolve().parent
RESULTS_PATH = BASE_DIR / "results.csv"
TEST_PASSWORD: Final[str] = "CourseWorkPassword!2026"
WRONG_PASSWORD: Final[str] = "WrongPassword123!"
RESULT_FIELDS: Final[list[str]] = [
    "algorithm",
    "parameters",
    "rounds",
    "avg_hash_ms",
    "avg_verify_ms",
    "correct_password",
    "wrong_password",
    "password_length",
]
BENCHMARK_CONFIGS: Final[list[dict[str, Any]]] = [
    {
        "algorithm": "bcrypt",
        "parameters": "cost=10",
        "kind": "bcrypt",
        "cost": 10,
    },
    {
        "algorithm": "bcrypt",
        "parameters": "cost=12",
        "kind": "bcrypt",
        "cost": 12,
    },
    {
        "algorithm": "scrypt",
        "parameters": "N=16384, r=8, p=1",
        "kind": "scrypt",
        "n": 16384,
        "r": 8,
        "p": 1,
        "dklen": 64,
    },
    {
        "algorithm": "scrypt",
        "parameters": "N=32768, r=8, p=1",
        "kind": "scrypt",
        "n": 32768,
        "r": 8,
        "p": 1,
        "dklen": 64,
    },
    {
        "algorithm": "argon2id",
        "parameters": "m=32768, t=2, p=2",
        "kind": "argon2id",
        "memory_cost": 32768,
        "time_cost": 2,
        "parallelism": 2,
        "hash_len": 32,
        "salt_len": 16,
    },
    {
        "algorithm": "argon2id",
        "parameters": "m=65536, t=3, p=4",
        "kind": "argon2id",
        "memory_cost": 65536,
        "time_cost": 3,
        "parallelism": 4,
        "hash_len": 32,
        "salt_len": 16,
    },
]


def ensure_results_file(results_path: Path = RESULTS_PATH) -> None:
    if results_path.exists():
        with results_path.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            header = next(reader, None)
            if header == RESULT_FIELDS:
                return

    with results_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RESULT_FIELDS)
        writer.writeheader()


def run_benchmark(
    rounds: int = 5,
    password: str = TEST_PASSWORD,
    results_path: Path = RESULTS_PATH,
) -> list[dict[str, float | int | str]]:
    ensure_results_file(results_path)
    results: list[dict[str, float | int | str]] = []

    for configuration in BENCHMARK_CONFIGS:
        hash_samples: list[float] = []
        verify_samples: list[float] = []
        correct_results: list[bool] = []
        wrong_results: list[bool] = []

        for _ in range(rounds):
            started_at = time.perf_counter()
            stored_hash = _hash_for_configuration(password, configuration)
            hash_samples.append((time.perf_counter() - started_at) * 1000)

            started_at = time.perf_counter()
            correct_results.append(verify_password(password, stored_hash))
            verify_samples.append((time.perf_counter() - started_at) * 1000)

            wrong_results.append(verify_password(WRONG_PASSWORD, stored_hash))

        results.append(
            {
                "algorithm": str(configuration["algorithm"]),
                "parameters": str(configuration["parameters"]),
                "rounds": rounds,
                "avg_hash_ms": round(statistics.mean(hash_samples), 3),
                "avg_verify_ms": round(statistics.mean(verify_samples), 3),
                "correct_password": "успішно" if all(correct_results) else "помилка",
                "wrong_password": "відхилено" if not any(wrong_results) else "помилка",
                "password_length": len(password),
            }
        )

    with results_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(results)

    return results


def read_results(results_path: Path = RESULTS_PATH) -> list[dict[str, str]]:
    ensure_results_file(results_path)
    with results_path.open("r", newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def _hash_for_configuration(password: str, configuration: dict[str, Any]) -> str:
    prepared_password = apply_pepper(password)
    password_bytes = prepared_password.encode("utf-8")
    kind = str(configuration["kind"])

    if kind == "bcrypt":
        return bcrypt.hashpw(
            password_bytes,
            bcrypt.gensalt(rounds=int(configuration["cost"])),
        ).decode("utf-8")

    if kind == "scrypt":
        n = int(configuration["n"])
        r = int(configuration["r"])
        p = int(configuration["p"])
        dklen = int(configuration["dklen"])
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password_bytes,
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=_get_scrypt_maxmem(n, r, p),
        )
        return (
            "scrypt$"
            f"n={n},r={r},p={p},dklen={dklen}$"
            f"{salt.hex()}$"
            f"{digest.hex()}"
        )

    hasher = PasswordHasher(
        time_cost=int(configuration["time_cost"]),
        memory_cost=int(configuration["memory_cost"]),
        parallelism=int(configuration["parallelism"]),
        hash_len=int(configuration["hash_len"]),
        salt_len=int(configuration["salt_len"]),
        type=Type.ID,
    )
    return hasher.hash(prepared_password)


def _get_scrypt_maxmem(n: int, r: int, p: int) -> int:
    return max(128 * n * r * p * 2, 64 * 1024 * 1024)


if __name__ == "__main__":
    benchmark_results = run_benchmark()
    print("Benchmark completed.")
    print(f"Default algorithm for app users: {DEFAULT_ALGORITHM}")
    for row in benchmark_results:
        print(row)
