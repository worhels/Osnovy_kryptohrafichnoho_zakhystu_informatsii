import hashlib


def inv_mod(value: int, modulus: int) -> int:
    value %= modulus

    if value == 0:
        raise ZeroDivisionError("No inverse for 0.")

    return pow(value, -1, modulus)


def hash_to_int(message: bytes, modulus: int) -> int:
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % modulus


def sign_toy(z: int, private_key: int, nonce: int, r: int, n: int) -> int:
    return (inv_mod(nonce, n) * (z + r * private_key)) % n


def recover_key(z1: int, s1: int, z2: int, s2: int, r: int, n: int) -> tuple[int, int]:
    recovered_nonce = ((z1 - z2) * inv_mod(s1 - s2, n)) % n
    recovered_private_key = ((s1 * recovered_nonce - z1) * inv_mod(r, n)) % n

    return recovered_nonce, recovered_private_key


def main() -> None:
    n = 1019
    private_key = 321
    reused_nonce = 77
    r = 456

    message_1 = b"payment=100"
    message_2 = b"payment=900"

    z1 = hash_to_int(message_1, n)
    z2 = hash_to_int(message_2, n)

    s1 = sign_toy(z1, private_key, reused_nonce, r, n)
    s2 = sign_toy(z2, private_key, reused_nonce, r, n)

    recovered_nonce, recovered_private_key = recover_key(z1, s1, z2, s2, r, n)

    print(f"n = {n}")
    print(f"r = {r}")
    print(f"message_1 = {message_1.decode()}")
    print(f"message_2 = {message_2.decode()}")
    print(f"s1 = {s1}")
    print(f"s2 = {s2}")
    print(f"True nonce k = {reused_nonce}")
    print(f"Recovered nonce k = {recovered_nonce}")
    print(f"True private key d = {private_key}")
    print(f"Recovered private key d = {recovered_private_key}")
    print(f"Result: {recovered_private_key == private_key}")


if __name__ == "__main__":
    main()
