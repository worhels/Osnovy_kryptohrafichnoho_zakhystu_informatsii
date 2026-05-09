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
    return (y * y - (x**3 + A * x + B)) % P_MOD == 0


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
