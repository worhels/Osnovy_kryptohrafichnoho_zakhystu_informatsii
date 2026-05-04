from pathlib import Path
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PRIVATE_KEY_FILE = Path("student_private.pem")
PUBLIC_KEY_FILE = Path("student_public.pem")

ENCRYPTED_KEY_FILE = Path("encrypted_session_key.bin")
AES_CIPHERTEXT_FILE = Path("aes_gcm_ciphertext.bin")
TASK5_RESULT_FILE = Path("task5-result.txt")

MESSAGE_TEXT = "Повідомлення, зашифроване AES-GCM після передачі ключа через RSA-OAEP."


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    private_key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Файл не містить RSA-закритий ключ.")

    return private_key


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    public_key = serialization.load_pem_public_key(path.read_bytes())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Файл не містить RSA-відкритий ключ.")

    return public_key


def main() -> None:
    private_key = load_private_key(PRIVATE_KEY_FILE)
    public_key = load_public_key(PUBLIC_KEY_FILE)

    session_key = os.urandom(32)

    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decrypted_session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    keys_match = session_key == decrypted_session_key

    aesgcm = AESGCM(decrypted_session_key)
    nonce = os.urandom(12)
    message = MESSAGE_TEXT.encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, message, None)
    decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)
    decrypted_text = decrypted_message.decode("utf-8")

    ENCRYPTED_KEY_FILE.write_bytes(encrypted_session_key)
    AES_CIPHERTEXT_FILE.write_bytes(nonce + ciphertext)

    TASK5_RESULT_FILE.write_text(
        "Завдання 5. RSA-KEM + AES-GCM\n"
        f"Початкове повідомлення: {MESSAGE_TEXT}\n"
        f"Довжина симетричного ключа: {len(session_key) * 8} біт\n"
        f"Довжина encrypted session key: {len(encrypted_session_key)} байт\n"
        f"Ключ після розшифрування збігається з початковим: {keys_match}\n"
        f"Розшифроване повідомлення: {decrypted_text}\n",
        encoding="utf-8",
    )

    print("Лабораторна робота №7")
    print("Завдання 5. Використання RSA для узгодження симетричного ключа")
    print(f"Файл відкритого ключа: {PUBLIC_KEY_FILE}")
    print(f"Файл закритого ключа: {PRIVATE_KEY_FILE}")
    print(f"Довжина симетричного ключа: {len(session_key) * 8} біт")
    print(f"Encrypted session key збережено у файл: {ENCRYPTED_KEY_FILE}")
    print(f"Довжина encrypted session key: {len(encrypted_session_key)} байт")
    print(f"Ключ після розшифрування збігається з початковим: {keys_match}")
    print("Алгоритм шифрування повідомлення: AES-GCM")
    print(f"Довжина nonce: {len(nonce)} байт")
    print(f"Довжина AES-GCM ciphertext: {len(ciphertext)} байт")
    print(f"AES-GCM ciphertext збережено у файл: {AES_CIPHERTEXT_FILE}")
    print(f"Розшифроване повідомлення: {decrypted_text}")
    print(f"Результат збережено у файл: {TASK5_RESULT_FILE}")


if __name__ == "__main__":
    main()