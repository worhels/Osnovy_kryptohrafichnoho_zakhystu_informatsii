from __future__ import annotations

from importlib import import_module
import sys
from typing import Final, Protocol, cast


class PasswordHasherProtocol(Protocol):
    def hash(self, password: str) -> str:
        ...

    def verify(self, hash: str, password: str) -> bool:
        ...


class PasswordHasherFactory(Protocol):
    def __call__(self) -> PasswordHasherProtocol:
        ...


DEMO_USERS: Final[dict[str, str]] = {
    "user1": "password123",
    "user2": "qwerty",
    "user3": "hello123",
    "user4": "admin123",
    "user5": "test123",
}


def create_password_hasher() -> PasswordHasherProtocol:
    argon2_module = import_module("argon2")
    password_hasher_class = cast(
        PasswordHasherFactory,
        getattr(argon2_module, "PasswordHasher"),
    )
    return password_hasher_class()


def load_verification_exceptions() -> tuple[type[Exception], ...]:
    exceptions_module = import_module("argon2.exceptions")
    exception_types: list[type[Exception]] = []

    for exception_name in ("VerifyMismatchError", "VerificationError"):
        exception_type = getattr(exceptions_module, exception_name, None)
        if isinstance(exception_type, type) and issubclass(exception_type, Exception):
            exception_types.append(exception_type)

    if not exception_types:
        raise RuntimeError("Не вдалося знайти винятки Argon2 для перевірки.")

    return tuple(exception_types)


def extract_salt_from_argon2_hash(encoded_hash: str) -> str:
    parts = encoded_hash.split("$")
    if len(parts) < 6:
        raise ValueError("Некоректний формат Argon2-хешу.")
    return parts[4]


def verify_password(
    password_hasher: PasswordHasherProtocol,
    encoded_hash: str,
    password: str,
) -> bool:
    verify_exceptions = load_verification_exceptions()

    try:
        return bool(password_hasher.verify(encoded_hash, password))
    except verify_exceptions:
        return False


def show_user_hashing_demo(
    password_hasher: PasswordHasherProtocol,
    username: str,
    password: str,
) -> None:
    encoded_hash = password_hasher.hash(password)
    extracted_salt = extract_salt_from_argon2_hash(encoded_hash)

    print("=" * 72)
    print(f"Користувач: {username}")
    print(f"Сіль (витягнута з Argon2-рядка): {extracted_salt}")
    print(f"Повний Argon2-хеш: {encoded_hash}")
    print(
        "Перевірка правильного пароля:",
        "успішна" if verify_password(password_hasher, encoded_hash, password) else "неуспішна",
    )
    print(
        "Перевірка неправильного пароля:",
        "успішна" if verify_password(password_hasher, encoded_hash, f"{password}_wrong") else "неуспішна",
    )


def main() -> None:
    try:
        password_hasher = create_password_hasher()
    except ModuleNotFoundError:
        print("Помилка: не знайдено пакет argon2-cffi.")
        print("Встановіть залежності командою:")
        print("python -m pip install -r requirements.txt")
        sys.exit(1)

    print("Лабораторна робота 6")
    print("Завдання 1: Хешування паролів за допомогою Argon2")

    for username, password in DEMO_USERS.items():
        show_user_hashing_demo(password_hasher, username, password)


if __name__ == "__main__":
    main()
