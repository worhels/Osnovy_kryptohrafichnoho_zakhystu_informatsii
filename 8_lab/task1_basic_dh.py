p = 23
g = 5

a = 6
b = 15

A = pow(g, a, p)
B = pow(g, b, p)

secret_A = pow(B, a, p)
secret_B = pow(A, b, p)

print("=== Task 1. Basic Diffie-Hellman ===")
print(f"p = {p}")
print(f"g = {g}")
print(f"Private key A: a = {a}")
print(f"Private key B: b = {b}")
print(f"Public key A = g^a mod p = {A}")
print(f"Public key B = g^b mod p = {B}")
print(f"Shared secret A = B^a mod p = {secret_A}")
print(f"Shared secret B = A^b mod p = {secret_B}")
print(f"Secrets are equal: {secret_A == secret_B}")