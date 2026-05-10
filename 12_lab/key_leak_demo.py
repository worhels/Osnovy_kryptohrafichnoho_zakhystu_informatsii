
# key_leak_demo.py
import hashlib

key = "leaked_key"
secret_data = "TOP SECRET"

cipher = hashlib.sha256((key+secret_data).encode()).hexdigest()
print("Cipher:", cipher)

recovered = hashlib.sha256((key+secret_data).encode()).hexdigest()

print("\n[ATTACKER]")
print("Recovered match:", recovered == cipher)
