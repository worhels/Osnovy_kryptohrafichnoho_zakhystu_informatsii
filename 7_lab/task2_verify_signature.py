from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


PUBLIC_KEY_FILE = Path("task_pub.pem")
MESSAGE_FILE = Path("task_message.txt")
SIGNATURE_FILE = Path("task_signature.txt")


def read_hex_file(path: Path) -> bytes:
    hex_text = path.read_text(encoding="utf-8").strip()
    return bytes.fromhex(hex_text)


def load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    public_key = load_pem_public_key(path.read_bytes())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Файл відкритого ключа не містить RSA-ключ.")

    return public_key


def main() -> None:
    public_key = load_rsa_public_key(PUBLIC_KEY_FILE)
    message = read_hex_file(MESSAGE_FILE)
    signature = read_hex_file(SIGNATURE_FILE)

    print("Лабораторна робота №7")
    print("Завдання 2. Перевірка цифрового підпису")
    print(f"Файл відкритого ключа: {PUBLIC_KEY_FILE}")
    print(f"Файл повідомлення: {MESSAGE_FILE}")
    print(f"Файл підпису: {SIGNATURE_FILE}")
    print(f"Довжина повідомлення: {len(message)} байт")
    print(f"Довжина підпису: {len(signature)} байт")

    try:
        decoded_message = message.decode("utf-8")
        print(f"Повідомлення після декодування: {decoded_message}")
    except UnicodeDecodeError:
        print("Повідомлення не вдалося декодувати як UTF-8.")

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        print("Результат перевірки: підпис дійсний.")
        print("Що перевіряє підпис: цілісність і автентичність повідомлення.")

    except InvalidSignature:
        print("Результат перевірки: підпис недійсний.")


if __name__ == "__main__":
    main()