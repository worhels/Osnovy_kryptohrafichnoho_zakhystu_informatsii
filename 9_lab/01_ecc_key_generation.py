from __future__ import annotations

from typing import Optional


Point = Optional[tuple[int, int]]

P_MOD = 9739
A = 497
B = 1768
G: Point = (1804, 5368)


def mod_inverse(value: int, modulus: int = P_MOD) -> int:
    value %= modulus

    if value == 0:
        raise ZeroDivisionError("No inverse for 0.")

    return pow(value, -1, modulus)


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True

    x, y = point
    left = (y * y) % P_MOD
    right = (x**3 + A * x + B) % P_MOD

    return left == right


def point_negation(point: Point) -> Point:
    if point is None:
        return None

    x, y = point
    return x, (-y) % P_MOD


def point_addition(first: Point, second: Point) -> Point:
    if first is None:
        return second

    if second is None:
        return first

    x1, y1 = first
    x2, y2 = second

    if x1 == x2 and (y1 + y2) % P_MOD == 0:
        return None

    if first == second:
        slope = ((3 * x1 * x1 + A) * mod_inverse(2 * y1)) % P_MOD
    else:
        slope = ((y2 - y1) * mod_inverse(x2 - x1)) % P_MOD

    x3 = (slope * slope - x1 - x2) % P_MOD
    y3 = (slope * (x1 - x3) - y1) % P_MOD

    return x3, y3


def scalar_multiplication(k: int, point: Point) -> Point:
    if k < 0:
        return scalar_multiplication(-k, point_negation(point))

    result: Point = None
    addend: Point = point

    while k > 0:
        if k & 1:
            result = point_addition(result, addend)

        addend = point_addition(addend, addend)
        k >>= 1

    return result


def main() -> None:
    if not is_on_curve(G):
        raise ValueError("Base point does not belong to the curve.")

    infinity: Point = None
    two_g = scalar_multiplication(2, G)

    assert point_addition(G, infinity) == G
    assert point_addition(infinity, G) == G
    assert point_addition(G, point_negation(G)) is None
    assert point_addition(G, G) == two_g
    assert is_on_curve(two_g)

    left = scalar_multiplication(7 + 11, G)
    right = point_addition(
        scalar_multiplication(7, G),
        scalar_multiplication(11, G),
    )

    assert left == right

    print(f"Curve parameters: p={P_MOD}, a={A}, b={B}")
    print(f"Base point G = {G}")
    print("Base point check: OK")
    print("Group invariants: OK")
    print(f"2G = {two_g}")
    print(f"7G + 11G = {right}")
    print(f"(7 + 11)G = {left}")

    private_keys = [2, 7, 19]

    print("Public keys:")
    for private_key in private_keys:
        public_key = scalar_multiplication(private_key, G)
        print(f"k = {private_key:2d} -> Q = {public_key}")


if __name__ == "__main__":
    main()