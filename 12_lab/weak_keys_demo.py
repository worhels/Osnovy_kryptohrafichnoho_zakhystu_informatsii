
# weak_keys_demo.py
import hashlib

private_key = "SECRET_PRIVATE_KEY"
message = "Important authenticated message"
signature = hashlib.sha256((private_key + message).encode()).hexdigest()

print("Message:", message)
print("Signature:", signature)

# attacker
attacker_key = private_key
fake_message = "Fake message from attacker"
fake_signature = hashlib.sha256((attacker_key + fake_message).encode()).hexdigest()

print("\n[ATTACK]")
print("Fake message:", fake_message)
print("Fake signature:", fake_signature)
