import time
import requests


BLOCK_SIZE = 16
ORACLE_URL = "https://aes.cryptohack.org/ecb_oracle/encrypt/"
RETRY_DELAY = 1.0
CANDIDATE_BYTES = (
    b"{}_"
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789"
    b"!@#$%^&*()-=+[]:;,.?/\\|~` '\""
)
SESSION = requests.Session()


def split_blocks(blob: bytes, size: int = BLOCK_SIZE) -> list[bytes]:
    return [blob[index:index + size] for index in range(0, len(blob), size)]


def get_block(blob: bytes, block_index: int, size: int = BLOCK_SIZE) -> bytes:
    start = block_index * size
    end = start + size
    return blob[start:end]


def encrypt_oracle(chunk: bytes) -> bytes:
    route = f"{ORACLE_URL}{chunk.hex()}/"

    while True:
        try:
            reply = SESSION.get(route, timeout=30)
            reply.raise_for_status()
            cipher_hex = reply.json()["ciphertext"]
            return bytes.fromhex(cipher_hex)
        except (requests.RequestException, KeyError, ValueError):
            print("Повтор запиту...", flush=True)
            time.sleep(RETRY_DELAY)


def build_probe_order() -> list[int]:
    priority = list(dict.fromkeys(CANDIDATE_BYTES))
    seen = set(priority)
    tail = [value for value in range(256) if value not in seen]
    return priority + tail


def find_next_byte(prefix: bytes, block_index: int, reference: bytes, probe_order: list[int]) -> int | None:
    for probe in probe_order:
        trial = encrypt_oracle(prefix + bytes([probe]))
        if get_block(trial, block_index) == reference:
            return probe
    return None


def recover_flag() -> bytes:
    secret = bytearray()
    probe_order = build_probe_order()

    while True:
        filler_len = BLOCK_SIZE - 1 - (len(secret) % BLOCK_SIZE)
        block_index = len(secret) // BLOCK_SIZE
        if filler_len == 0:
            filler_len = BLOCK_SIZE
            block_index += 1
        filler = b"A" * filler_len
        reference = get_block(encrypt_oracle(filler), block_index)
        prefix = filler + bytes(secret)
        guessed_byte = find_next_byte(prefix, block_index, reference, probe_order)

        if guessed_byte is None:
            print("Не вдалося знайти наступний байт FLAG", flush=True)
            break

        secret.append(guessed_byte)
        symbol = bytes([guessed_byte]).decode("utf-8", errors="replace")
        current_flag = secret.decode("utf-8", errors="replace")
        print(f"Знайдений байт: 0x{guessed_byte:02x} ({symbol})", flush=True)
        print(f"Проміжний результат FLAG: {current_flag}", flush=True)

        if guessed_byte == ord("}"):
            break

    return bytes(secret)


def main() -> None:
    flag = recover_flag().decode("utf-8", errors="replace")
    print(f"Знайдений FLAG: {flag}")


if __name__ == "__main__":
    main()
