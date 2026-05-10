import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def h(value: bytes) -> str:
    return value.hex()[:32]


def kdf_chain(chain_key: bytes):
    next_chain_key = hmac.new(chain_key, b"chain", hashlib.sha256).digest()
    message_key = hmac.new(chain_key, b"message", hashlib.sha256).digest()
    return next_chain_key, message_key


def kdf_root(root_key: bytes, dh_output: bytes):
    new_root_key = hmac.new(root_key, b"root" + dh_output, hashlib.sha256).digest()
    new_chain_key = hmac.new(new_root_key, b"chain-key", hashlib.sha256).digest()
    return new_root_key, new_chain_key


def encrypt(message_key: bytes, plaintext: str):
    aead = ChaCha20Poly1305(message_key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, plaintext.encode("utf-8"), b"lab11-signal-demo")
    return nonce, ciphertext


def decrypt(message_key: bytes, nonce: bytes, ciphertext: bytes):
    aead = ChaCha20Poly1305(message_key)
    plaintext = aead.decrypt(nonce, ciphertext, b"lab11-signal-demo")
    return plaintext.decode("utf-8")


print("========== SIGNAL DOUBLE RATCHET PRACTICE DEMO ==========")

print("\n[1] Initial X25519 Diffie-Hellman key exchange")

alice_dh_private = X25519PrivateKey.generate()
bob_dh_private = X25519PrivateKey.generate()

alice_dh_public = alice_dh_private.public_key()
bob_dh_public = bob_dh_private.public_key()

alice_shared = alice_dh_private.exchange(bob_dh_public)
bob_shared = bob_dh_private.exchange(alice_dh_public)

print("Alice shared secret hash:", h(alice_shared))
print("Bob shared secret hash:  ", h(bob_shared))
print("Shared secrets equal:    ", alice_shared == bob_shared)

root_key = hashlib.sha256(b"initial-root-key" + alice_shared).digest()
alice_sending_chain = hmac.new(root_key, b"alice-sending-chain", hashlib.sha256).digest()
bob_receiving_chain = hmac.new(root_key, b"alice-sending-chain", hashlib.sha256).digest()

print("\n[2] Symmetric-key ratchet: each message gets a new key")

messages = [
    "Message 1: OpenSSH uses keys for authentication",
    "Message 2: WireGuard identifies peers by public keys",
    "Message 3: Signal changes message keys over time",
]

captured_message_key_2 = None

for index, text in enumerate(messages, start=1):
    alice_sending_chain, alice_message_key = kdf_chain(alice_sending_chain)
    bob_receiving_chain, bob_message_key = kdf_chain(bob_receiving_chain)

    nonce, ciphertext = encrypt(alice_message_key, text)
    decrypted = decrypt(bob_message_key, nonce, ciphertext)

    print(f"\nMessage {index}")
    print("Alice message key:", h(alice_message_key))
    print("Bob message key:  ", h(bob_message_key))
    print("Keys equal:       ", alice_message_key == bob_message_key)
    print("Ciphertext hash:  ", h(hashlib.sha256(ciphertext).digest()))
    print("Bob decrypted:    ", decrypted)

    if index == 2:
        captured_message_key_2 = alice_message_key

    del alice_message_key
    del bob_message_key

print("\n[3] Compromise simulation")

assert captured_message_key_2 is not None
print("Attacker captured only Message 2 key:", h(captured_message_key_2))
print("This key is not reused for Message 1 or Message 3.")
print("Old message keys were deleted after use.")
print("Result: compromise of one message key is local, not global.")

print("\n[4] Diffie-Hellman ratchet: Bob sends a new DH public key")

bob_new_dh_private = X25519PrivateKey.generate()
bob_new_dh_public = bob_new_dh_private.public_key()

alice_new_dh_output = alice_dh_private.exchange(bob_new_dh_public)
bob_new_dh_output = bob_new_dh_private.exchange(alice_dh_public)

print("Alice new DH output hash:", h(alice_new_dh_output))
print("Bob new DH output hash:  ", h(bob_new_dh_output))
print("New DH outputs equal:    ", alice_new_dh_output == bob_new_dh_output)

old_root_key = root_key
alice_root_key, alice_new_chain = kdf_root(old_root_key, alice_new_dh_output)
bob_root_key, bob_new_chain = kdf_root(old_root_key, bob_new_dh_output)

alice_new_chain, alice_new_message_key = kdf_chain(alice_new_chain)
bob_new_chain, bob_new_message_key = kdf_chain(bob_new_chain)
root_key = alice_root_key

nonce, ciphertext = encrypt(alice_new_message_key, "Message 4: New DH ratchet created new cryptographic state")
decrypted = decrypt(bob_new_message_key, nonce, ciphertext)

print("\nMessage 4 after DH ratchet")
print("New root key:     ", h(root_key))
print("Bob root matches: ", alice_root_key == bob_root_key)
print("New message key:  ", h(alice_new_message_key))
print("Bob key matches:  ", alice_new_message_key == bob_new_message_key)
print("Bob decrypted:    ", decrypted)

print("\n[SUCCESS] Signal ratchet demo completed")
print("Forward Secrecy shown: old keys are not recovered from current keys")
print("Post-compromise recovery idea shown: new DH ratchet creates a new state")
