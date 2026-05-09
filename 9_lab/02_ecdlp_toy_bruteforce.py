from ecc_core import G, Point, is_on_curve, scalar_multiplication


def find_private_key(target: Point, search_limit: int) -> int:
    for candidate in range(1, search_limit + 1):
        if scalar_multiplication(candidate, G) == target:
            return candidate

    raise ValueError("Private key was not found in the selected range.")


def main() -> None:
    secret_k = 83
    search_limit = 200

    public_key = scalar_multiplication(secret_k, G)

    if not is_on_curve(public_key):
        raise ValueError("Generated public key does not belong to the curve.")

    found_k = find_private_key(public_key, search_limit)

    print(f"Base point G = {G}")
    print(f"Target Q = {public_key}")
    print(f"Search range: 1..{search_limit}")
    print(f"True k = {secret_k}")
    print(f"Found k = {found_k}")
    print(f"Result: {found_k == secret_k}")


if __name__ == "__main__":
    main()
