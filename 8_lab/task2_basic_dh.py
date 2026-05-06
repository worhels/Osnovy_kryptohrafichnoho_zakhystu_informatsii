p = 23
g = 5

a = 6
b = 15

A = 8
B = 19

m1 = 7
m2 = 3

normal_secret_A = pow(B, a, p)
normal_secret_B = pow(A, b, p)

mitm_secret_A = pow(m2, a, p)
mitm_secret_B = pow(m1, b, p)

print("=== Task 2. MITM attack on Diffie-Hellman ===")
print(f"p = {p}")
print(f"g = {g}")
print(f"Private key A: a = {a}")
print(f"Private key B: b = {b}")
print()
print("Normal Diffie-Hellman exchange:")
print(f"Public key A = {A}")
print(f"Public key B = {B}")
print(f"Normal shared secret A = {normal_secret_A}")
print(f"Normal shared secret B = {normal_secret_B}")
print(f"Normal secrets are equal: {normal_secret_A == normal_secret_B}")
print()
print("MITM substitution:")
print(f"Attacker sends m1 = {m1} to B instead of A")
print(f"Attacker sends m2 = {m2} to A instead of B")
print()
print(f"Secret calculated by A with substituted m2: {mitm_secret_A}")
print(f"Secret calculated by B with substituted m1: {mitm_secret_B}")
print(f"MITM secrets are equal: {mitm_secret_A == mitm_secret_B}")
print()
print("Result:")
print("A and B no longer share the same secret directly.")
print("Attacker creates two separate key agreements: A <-> M and B <-> M.")