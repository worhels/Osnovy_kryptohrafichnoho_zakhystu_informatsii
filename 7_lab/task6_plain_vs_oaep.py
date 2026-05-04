from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


PUBLIC_KEY_FILE = Path("task_pub.pem")

PLAIN_RSA_1_FILE = Path("plain_rsa_1.bin")
PLAIN_RSA_2_FILE = Path("plain_rsa_2.bin")
OAEP_1_FILE = Path("oaep_1.bin")
OAEP_2_FILE = Path("oaep_2.bin")
RESULT_FILE = Path("task6-result.txt")

MESSAGE_TEXT = "Test message for RSA vulnerability analysis"


def load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    public_key = load_pem_public_key(path.read_bytes())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Файл відкритого ключа не містить RSA-ключ.")

    return public_key


def plain_rsa_encrypt(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e

    message_int = int.from_bytes(message, byteorder="big")

    if message_int >= n:
        raise ValueError("Повідомлення занадто велике для plain RSA.")

    ciphertext_int = pow(message_int, e, n)
    key_size_bytes = (public_key.key_size + 7) // 8

    return ciphertext_int.to_bytes(key_size_bytes, byteorder="big")


def oaep_encrypt(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def main() -> None:
    public_key = load_rsa_public_key(PUBLIC_KEY_FILE)
    message = MESSAGE_TEXT.encode("utf-8")

    plain_ciphertext_1 = plain_rsa_encrypt(public_key, message)
    plain_ciphertext_2 = plain_rsa_encrypt(public_key, message)

    oaep_ciphertext_1 = oaep_encrypt(public_key, message)
    oaep_ciphertext_2 = oaep_encrypt(public_key, message)

    plain_equal = plain_ciphertext_1 == plain_ciphertext_2
    oaep_equal = oaep_ciphertext_1 == oaep_ciphertext_2

    PLAIN_RSA_1_FILE.write_bytes(plain_ciphertext_1)
    PLAIN_RSA_2_FILE.write_bytes(plain_ciphertext_2)
    OAEP_1_FILE.write_bytes(oaep_ciphertext_1)
    OAEP_2_FILE.write_bytes(oaep_ciphertext_2)

    RESULT_FILE.write_text(
        "Завдання 6. Аналіз вразливостей RSA\n"
        f"Повідомлення: {MESSAGE_TEXT}\n"
        f"Plain RSA ciphertext-и однакові: {plain_equal}\n"
        f"RSA-OAEP ciphertext-и однакові: {oaep_equal}\n",
        encoding="utf-8",
    )

    print("Лабораторна робота №7")
    print("Завдання 6. Аналіз вразливостей RSA")
    print(f"Файл відкритого ключа: {PUBLIC_KEY_FILE}")
    print(f"Повідомлення: {MESSAGE_TEXT}")
    print(f"Довжина повідомлення: {len(message)} байт")
    print()
    print("Крок 1. Plain RSA без padding")
    print(f"Plain RSA ciphertext 1 збережено у файл: {PLAIN_RSA_1_FILE}")
    print(f"Plain RSA ciphertext 2 збережено у файл: {PLAIN_RSA_2_FILE}")
    print(f"Plain RSA ciphertext-и однакові: {plain_equal}")
    print(f"Перші 64 hex-символи plain ciphertext 1: {plain_ciphertext_1.hex()[:64]}...")
    print(f"Перші 64 hex-символи plain ciphertext 2: {plain_ciphertext_2.hex()[:64]}...")
    print()
    print("Крок 2. RSA-OAEP")
    print(f"RSA-OAEP ciphertext 1 збережено у файл: {OAEP_1_FILE}")
    print(f"RSA-OAEP ciphertext 2 збережено у файл: {OAEP_2_FILE}")
    print(f"RSA-OAEP ciphertext-и однакові: {oaep_equal}")
    print(f"Перші 64 hex-символи OAEP ciphertext 1: {oaep_ciphertext_1.hex()[:64]}...")
    print(f"Перші 64 hex-символи OAEP ciphertext 2: {oaep_ciphertext_2.hex()[:64]}...")
    print()
    print(f"Результат збережено у файл: {RESULT_FILE}")


if __name__ == "__main__":
    main()