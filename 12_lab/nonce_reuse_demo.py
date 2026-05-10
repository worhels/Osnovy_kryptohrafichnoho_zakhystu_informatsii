
# nonce_reuse_demo.py
import hashlib

key = "secret"
nonce = "fixed_nonce"

m1 = "Message One"
m2 = "Message Two"

c1 = hashlib.sha256((key+nonce+m1).encode()).hexdigest()
c2 = hashlib.sha256((key+nonce+m2).encode()).hexdigest()

print("Ciphertext1:", c1)
print("Ciphertext2:", c2)
print("\nNonce reused → danger")
