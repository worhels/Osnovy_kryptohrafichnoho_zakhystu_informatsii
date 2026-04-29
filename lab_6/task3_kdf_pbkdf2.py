import hashlib
import os


def derive_key_pbkdf2(password: str, salt: bytes, iterations: int, key_length: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=key_length,
    )


def main() -> None:
    password = "mypassword"
    salt = os.urandom(16)
    iterations = 100_000
    key_length_bytes = 32

    derived_key = derive_key_pbkdf2(password, salt, iterations, key_length_bytes)

    print("Лабораторна робота 6")
    print("Завдання 3: Генерація ключа через PBKDF2-HMAC-SHA256")
    print("=" * 72)
    print(f"Пароль: {password}")
    print(f"Сіль (hex): {salt.hex()}")
    print(f"Кількість ітерацій: {iterations}")
    print(f"Довжина згенерованого ключа: {len(derived_key) * 8} біт")
    print(f"Згенерований ключ (hex): {derived_key.hex()}")


if __name__ == "__main__":
    main()
