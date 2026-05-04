from typing import Optional


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1

    gcd_value, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd_value, x, y


def modular_inverse(a: int, m: int) -> tuple[Optional[int], int]:
    gcd_value, x, _ = extended_gcd(a, m)

    if gcd_value != 1:
        return None, gcd_value

    return x % m, gcd_value


a = 132
n = 1663

inverse, gcd_value = modular_inverse(a, n)

print("Лабораторна робота №7")
print("Завдання 1. Математична основа RSA: обернений елемент")
print("Варіант: 13")
print(f"a = {a}")
print(f"n = {n}")
print(f"gcd({a}, {n}) = {gcd_value}")

if inverse is None:
    print("Оберненого елемента не існує.")
else:
    print(f"Обернений елемент: {inverse}")
    print(f"Перевірка: ({a} * {inverse}) % {n} = {(a * inverse) % n}")