import hashlib
import hmac
import os


def compute_hmac_sha256(secret_key: bytes, message: str) -> bytes:
    return hmac.new(secret_key, message.encode("utf-8"), hashlib.sha256).digest()


def verify_hmac(expected_mac: bytes, secret_key: bytes, message: str) -> bool:
    actual_mac = compute_hmac_sha256(secret_key, message)
    return hmac.compare_digest(expected_mac, actual_mac)


def main() -> None:
    secret_key = os.urandom(32)
    original_message = "Transfer 1000 UAH to user5"
    modified_message = "Transfer 9000 UAH to user5"

    original_mac = compute_hmac_sha256(secret_key, original_message)
    modified_mac = compute_hmac_sha256(secret_key, modified_message)

    print("Лабораторна робота 6")
    print("Завдання 2: HMAC-SHA256")
    print("=" * 72)
    print(f"Секретний ключ (hex): {secret_key.hex()}")
    print(f"Оригінальне повідомлення: {original_message}")
    print(f"Оригінальний MAC: {original_mac.hex()}")
    print("-" * 72)
    print(f"Модифіковане повідомлення: {modified_message}")
    print(f"MAC модифікованого повідомлення: {modified_mac.hex()}")
    print("-" * 72)
    print(
        "Результат перевірки оригінального повідомлення:",
        "успішно" if verify_hmac(original_mac, secret_key, original_message) else "помилка",
    )
    print(
        "Результат перевірки модифікованого повідомлення:",
        "успішно" if verify_hmac(original_mac, secret_key, modified_message) else "помилка",
    )


if __name__ == "__main__":
    main()
