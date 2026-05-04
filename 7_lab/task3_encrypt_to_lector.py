from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


PUBLIC_KEY_FILE = Path("task_pub.pem")
OUTPUT_FILE = Path("encrypted_message.bin")

MESSAGE_TEXT = "Я зашифрував це повідомлення власноруч"


def load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    public_key = load_pem_public_key(path.read_bytes())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Файл відкритого ключа не містить RSA-ключ.")

    return public_key


def main() -> None:
    public_key = load_rsa_public_key(PUBLIC_KEY_FILE)
    message = MESSAGE_TEXT.encode("utf-8")

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    OUTPUT_FILE.write_bytes(ciphertext)

    print("Лабораторна робота №7")
    print("Завдання 3. Шифрування повідомлення лектору")
    print(f"Файл відкритого ключа: {PUBLIC_KEY_FILE}")
    print(f"Повідомлення: {MESSAGE_TEXT}")
    print(f"Довжина повідомлення: {len(message)} байт")
    print("Алгоритм шифрування: RSA-OAEP")
    print("Хеш-функція: SHA-256")
    print(f"Довжина ciphertext: {len(ciphertext)} байт")
    print(f"Зашифроване повідомлення збережено у файл: {OUTPUT_FILE}")
    print(f"Перші 64 hex-символи ciphertext: {ciphertext.hex()[:64]}...")


if __name__ == "__main__":
    main()