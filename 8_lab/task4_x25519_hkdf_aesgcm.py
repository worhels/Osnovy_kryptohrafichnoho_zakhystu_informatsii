import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


priv_A = x25519.X25519PrivateKey.generate()
priv_B = x25519.X25519PrivateKey.generate()

pub_A = priv_A.public_key()
pub_B = priv_B.public_key()

pub_A_bytes = pub_A.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

pub_B_bytes = pub_B.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

ss_A = priv_A.exchange(pub_B)
ss_B = priv_B.exchange(pub_A)

session_key_A = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"lab8-handshake"
).derive(ss_A)

session_key_B = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"lab8-handshake"
).derive(ss_B)

aes = AESGCM(session_key_A)
nonce = os.urandom(12)

plaintext = b"Test message"
ciphertext = aes.encrypt(nonce, plaintext, None)
decrypted = AESGCM(session_key_B).decrypt(nonce, ciphertext, None)

print("=== Task 4. X25519 -> HKDF -> session key -> AES-GCM ===")
print("Generated X25519 key pairs for A and B")
print()
print(f"Public key A length: {len(pub_A_bytes)} bytes")
print(f"Public key B length: {len(pub_B_bytes)} bytes")
print(f"Public key A: {pub_A_bytes.hex()}")
print(f"Public key B: {pub_B_bytes.hex()}")
print()
print(f"Shared secret A length: {len(ss_A)} bytes")
print(f"Shared secret B length: {len(ss_B)} bytes")
print(f"Shared secrets are equal: {ss_A == ss_B}")
print()
print(f"Session key A length: {len(session_key_A)} bytes")
print(f"Session key B length: {len(session_key_B)} bytes")
print(f"Session key A: {session_key_A.hex()}")
print(f"Session key B: {session_key_B.hex()}")
print(f"Session keys are equal: {session_key_A == session_key_B}")
print()
print("AES-GCM encryption:")
print(f"Nonce length: {len(nonce)} bytes")
print(f"Nonce: {nonce.hex()}")
print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted: {decrypted}")
print(f"Decryption successful: {decrypted == plaintext}")