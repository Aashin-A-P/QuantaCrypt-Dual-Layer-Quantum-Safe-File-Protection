# ==========================================================
# pqc_kyber.py — Post-Quantum Key Encapsulation (Kyber)
# ==========================================================

from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

# ----------------------------------------------------------
# Generate Kyber keypair
# ----------------------------------------------------------
def kyber_generate_keypair():
    public_key, secret_key = generate_keypair()
    return public_key, secret_key

# ----------------------------------------------------------
# Encapsulate
# ----------------------------------------------------------
def kyber_encapsulate(public_key: bytes):
    ciphertext, shared_secret = encrypt(public_key)
    return ciphertext, shared_secret

# ----------------------------------------------------------
# Decapsulate
# ----------------------------------------------------------
def kyber_decapsulate(ciphertext: bytes, secret_key: bytes):
    shared_secret = decrypt(ciphertext, secret_key)
    return shared_secret
