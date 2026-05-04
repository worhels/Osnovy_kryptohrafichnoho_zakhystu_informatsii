from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PRIVATE_KEY_FILE = Path("student_private.pem")
PUBLIC_KEY_FILE = Path("student_public.pem")
ENCRYPTED_FILE = Path("student_encrypted_message.bin")
RESULT_FILE = Path("task-2-message.txt")

MESSAGE_TEXT = "Повідомлення для студента, зашифроване його відкритим ключем."


def generate_student_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    PRIVATE_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    return private_key, public_key


def encrypt_for_student(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_private_key(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def main() -> None:
    private_key, public_key = generate_student_keys()

    message = MESSAGE_TEXT.encode("utf-8")

    encrypted_message = encrypt_for_student(public_key, message)
    ENCRYPTED_FILE.write_bytes(encrypted_message)

    decrypted_message = decrypt_with_private_key(private_key, encrypted_message)
    decrypted_text = decrypted_message.decode("utf-8")

    RESULT_FILE.write_text(
        "Завдання 4. Розшифрування повідомлення\n"
        f"Відкрите повідомлення: {MESSAGE_TEXT}\n"
        f"Зашифроване повідомлення збережено у файл: {ENCRYPTED_FILE}\n"
        f"Розшифроване повідомлення: {decrypted_text}\n",
        encoding="utf-8",
    )

    print("Лабораторна робота №7")
    print("Завдання 4. Розшифрування повідомлення")
    print(f"Закритий ключ збережено у файл: {PRIVATE_KEY_FILE}")
    print(f"Відкритий ключ збережено у файл: {PUBLIC_KEY_FILE}")
    print(f"Відкрите повідомлення: {MESSAGE_TEXT}")
    print(f"Зашифроване повідомлення збережено у файл: {ENCRYPTED_FILE}")
    print(f"Довжина ciphertext: {len(encrypted_message)} байт")
    print(f"Розшифроване повідомлення: {decrypted_text}")
    print(f"Результат збережено у файл: {RESULT_FILE}")


if __name__ == "__main__":
    main()