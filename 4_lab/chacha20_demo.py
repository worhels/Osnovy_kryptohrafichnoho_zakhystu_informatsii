MASK32 = 0xFFFFFFFF
CONSTANTS = b"expand 32-byte k"


def rotate_left(value: int, shift: int) -> int:
    value &= MASK32
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 16)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 12)

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 8)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 7)


def bytes_to_words(data: bytes) -> list[int]:
    return [int.from_bytes(data[index:index + 4], "little") for index in range(0, len(data), 4)]


def words_to_bytes(words: list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def create_initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    if len(key) != 32:
        raise ValueError("Ключ повинен містити 32 байти")
    if len(nonce) != 12:
        raise ValueError("Nonce повинен містити 12 байтів")
    constants = bytes_to_words(CONSTANTS)
    key_words = bytes_to_words(key)
    nonce_words = bytes_to_words(nonce)
    return constants + key_words + [counter & MASK32] + nonce_words


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    initial_state = create_initial_state(key, counter, nonce)
    working_state = initial_state[:]

    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    result = [(working_state[index] + initial_state[index]) & MASK32 for index in range(16)]
    return words_to_bytes(result)


def generate_keystream(length: int, key: bytes, counter: int, nonce: bytes) -> bytes:
    stream = bytearray()
    block_counter = counter
    while len(stream) < length:
        stream.extend(chacha20_block(key, block_counter, nonce))
        block_counter = (block_counter + 1) & MASK32
    return bytes(stream[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(plaintext: str | bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    plaintext_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    keystream = generate_keystream(len(plaintext_bytes), key, counter, nonce)
    return xor_bytes(plaintext_bytes, keystream)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    keystream = generate_keystream(len(ciphertext), key, counter, nonce)
    return xor_bytes(ciphertext, keystream)


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def test_one() -> bool:
    plaintext = "ChaCha20 тест українською мовою"
    key = bytes.fromhex(
        "000102030405060708090A0B0C0D0E0F"
        "101112131415161718191A1B1C1D1E1F"
    )
    nonce = bytes.fromhex("000000090000004A00000000")
    counter = 1
    ciphertext = encrypt(plaintext, key, nonce, counter)
    decrypted = decrypt(ciphertext, key, nonce, counter).decode("utf-8")
    success = decrypted == plaintext

    print("Тест 1 — базове шифрування")
    print(f"Відкритий текст: {plaintext}")
    print(f"Ключ: {bytes_to_hex(key)}")
    print(f"Nonce: {bytes_to_hex(nonce)}")
    print(f"Лічильник: {counter}")
    print(f"Шифртекст: {bytes_to_hex(ciphertext)}")
    print(f"Розшифрований текст: {decrypted}")
    print(f"Перевірка: {'співпадає' if success else 'не співпадає'}")
    print()
    return success


def test_two() -> bool:
    plaintext = "Однаковий текст для перевірки nonce"
    key = bytes.fromhex(
        "1F1E1D1C1B1A19181716151413121110"
        "0F0E0D0C0B0A09080706050403020100"
    )
    nonce_one = bytes.fromhex("000000000000000000000001")
    nonce_two = bytes.fromhex("000000000000000000000002")
    counter = 7
    ciphertext_one = encrypt(plaintext, key, nonce_one, counter)
    ciphertext_two = encrypt(plaintext, key, nonce_two, counter)
    success = ciphertext_one != ciphertext_two

    print("Тест 2 — зміна nonce")
    print(f"Відкритий текст: {plaintext}")
    print(f"Ключ: {bytes_to_hex(key)}")
    print(f"Nonce 1: {bytes_to_hex(nonce_one)}")
    print(f"Nonce 2: {bytes_to_hex(nonce_two)}")
    print(f"Лічильник: {counter}")
    print(f"Шифртекст 1: {bytes_to_hex(ciphertext_one)}")
    print(f"Шифртекст 2: {bytes_to_hex(ciphertext_two)}")
    print(f"Перевірка: {'шифртексти різні' if success else 'не співпадає'}")
    print()
    return success


def test_three() -> bool:
    plaintext = "Однаковий текст для перевірки counter"
    key = bytes.fromhex(
        "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
        "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
    )
    nonce = bytes.fromhex("112233445566778899AABBCC")
    counter_one = 1
    counter_two = 2
    ciphertext_one = encrypt(plaintext, key, nonce, counter_one)
    ciphertext_two = encrypt(plaintext, key, nonce, counter_two)
    success = ciphertext_one != ciphertext_two

    print("Тест 3 — зміна counter")
    print(f"Відкритий текст: {plaintext}")
    print(f"Ключ: {bytes_to_hex(key)}")
    print(f"Nonce: {bytes_to_hex(nonce)}")
    print(f"Лічильник 1: {counter_one}")
    print(f"Лічильник 2: {counter_two}")
    print(f"Шифртекст 1: {bytes_to_hex(ciphertext_one)}")
    print(f"Шифртекст 2: {bytes_to_hex(ciphertext_two)}")
    print(f"Перевірка: {'шифртексти різні' if success else 'не співпадає'}")
    print()
    return success


def main() -> None:
    test_one()
    test_two()
    test_three()
    print("Підсумок: тести ChaCha20 виконано")


if __name__ == "__main__":
    main()