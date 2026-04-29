SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]
RCON1 = 0x80
RCON2 = 0x30
IRREDUCIBLE = 0b10011


def split_nibbles(value: int) -> list[int]:
    return [(value >> shift) & 0xF for shift in (12, 8, 4, 0)]


def join_nibbles(nibbles: list[int]) -> int:
    return (
        (nibbles[0] << 12)
        | (nibbles[1] << 8)
        | (nibbles[2] << 4)
        | nibbles[3]
    )


def state_to_matrix(state: int) -> list[list[int]]:
    n0, n1, n2, n3 = split_nibbles(state)
    return [[n0, n2], [n1, n3]]


def matrix_to_state(matrix: list[list[int]]) -> int:
    return join_nibbles([matrix[0][0], matrix[1][0], matrix[0][1], matrix[1][1]])


def rotate_nibble(byte: int) -> int:
    return ((byte << 4) & 0xF0) | ((byte >> 4) & 0x0F)


def substitute_byte(byte: int) -> int:
    high = SBOX[(byte >> 4) & 0xF]
    low = SBOX[byte & 0xF]
    return (high << 4) | low


def gf_multiply(a: int, b: int) -> int:
    result = 0
    left = a & 0xF
    right = b & 0xF
    for _ in range(4):
        if right & 1:
            result ^= left
        right >>= 1
        carry = left & 0x8
        left = (left << 1) & 0xF
        if carry:
            left ^= IRREDUCIBLE & 0xF
    return result & 0xF


def AddRoundKey(state: int, round_key: int) -> int:
    return state ^ round_key


def SubNibble(state: int) -> int:
    return join_nibbles([SBOX[nibble] for nibble in split_nibbles(state)])


def InvSubNibble(state: int) -> int:
    return join_nibbles([INV_SBOX[nibble] for nibble in split_nibbles(state)])


def ShiftRows(state: int) -> int:
    matrix = state_to_matrix(state)
    matrix[1] = [matrix[1][1], matrix[1][0]]
    return matrix_to_state(matrix)


def InvShiftRows(state: int) -> int:
    matrix = state_to_matrix(state)
    matrix[1] = [matrix[1][1], matrix[1][0]]
    return matrix_to_state(matrix)


def MixColumns(state: int) -> int:
    matrix = state_to_matrix(state)
    mixed = [[0, 0], [0, 0]]
    for column in range(2):
        top = matrix[0][column]
        bottom = matrix[1][column]
        mixed[0][column] = top ^ gf_multiply(0x4, bottom)
        mixed[1][column] = gf_multiply(0x4, top) ^ bottom
    return matrix_to_state(mixed)


def InvMixColumns(state: int) -> int:
    matrix = state_to_matrix(state)
    mixed = [[0, 0], [0, 0]]
    for column in range(2):
        top = matrix[0][column]
        bottom = matrix[1][column]
        mixed[0][column] = gf_multiply(0x9, top) ^ gf_multiply(0x2, bottom)
        mixed[1][column] = gf_multiply(0x2, top) ^ gf_multiply(0x9, bottom)
    return matrix_to_state(mixed)


def KeyExpansion(key: int) -> list[int]:
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF
    w2 = w0 ^ RCON1 ^ substitute_byte(rotate_nibble(w1))
    w3 = w2 ^ w1
    w4 = w2 ^ RCON2 ^ substitute_byte(rotate_nibble(w3))
    w5 = w4 ^ w3
    return [
        (w0 << 8) | w1,
        (w2 << 8) | w3,
        (w4 << 8) | w5,
    ]


def encrypt(plaintext: int, key: int) -> int:
    round_keys = KeyExpansion(key)
    state = AddRoundKey(plaintext, round_keys[0])
    state = SubNibble(state)
    state = ShiftRows(state)
    state = MixColumns(state)
    state = AddRoundKey(state, round_keys[1])
    state = SubNibble(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, round_keys[2])
    return state


def decrypt(ciphertext: int, key: int) -> int:
    round_keys = KeyExpansion(key)
    state = AddRoundKey(ciphertext, round_keys[2])
    state = InvShiftRows(state)
    state = InvSubNibble(state)
    state = AddRoundKey(state, round_keys[1])
    state = InvMixColumns(state)
    state = InvShiftRows(state)
    state = InvSubNibble(state)
    state = AddRoundKey(state, round_keys[0])
    return state


def to_binary16(value: int) -> str:
    return format(value, "016b")


def to_hex4(value: int) -> str:
    return format(value, "04X")


def format_value(value: int) -> str:
    return f"{to_binary16(value)} (0x{to_hex4(value)})"


def run_test(index: int, plaintext: int, key: int, expected_ciphertext: int | None = None) -> bool:
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    success = decrypted == plaintext
    if expected_ciphertext is not None:
        success = success and ciphertext == expected_ciphertext
    print(f"Тест {index}")
    print(f"Відкритий текст: {format_value(plaintext)}")
    print(f"Ключ: {format_value(key)}")
    print(f"Шифртекст: {format_value(ciphertext)}")
    print(f"Розшифрований текст: {format_value(decrypted)}")
    print(f"Перевірка: {'співпадає' if success else 'не співпадає'}")
    print()
    return success


def run_tests() -> None:
    tests: list[tuple[int, int, int, int | None]] = [
        (1, 0xD728, 0x4AF5, 0x24EC),
        (2, 0x6F6B, 0xA73B, None),
        (3, 0x0000, 0xFFFF, None),
        (4, 0x1234, 0x5678, None),
    ]
    results: list[bool] = []
    for index, plaintext, key, expected_ciphertext in tests:
        results.append(run_test(index, plaintext, key, expected_ciphertext))
    print(f"Підсумок: {'усі тести пройдено' if all(results) else 'є помилки у тестах'}")


if __name__ == "__main__":
    run_tests()
