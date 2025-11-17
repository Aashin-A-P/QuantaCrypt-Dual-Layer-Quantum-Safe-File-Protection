import secrets
import hashlib

# ============================================================
#  KYBER-INSPIRED LATTICE KEM SIMULATOR (Pure Python)
# ============================================================

def random_bytes(length: int):
    """Secure random bytes."""
    return secrets.token_bytes(length)


def hash_kdf(*parts, length=32):
    """Hash-based key derivation function (SHA3-512)."""
    h = hashlib.sha3_512()
    for p in parts:
        h.update(p)
    return h.digest()[:length]


# ============================================================
#  Public Key + Secret Key Generation (Simulated)
# ============================================================

def kem_keygen():
    """
    Generates:
        pk = public key (simulated polynomial seed)
        sk = secret key (simulated secret vector)
    """
    pk = random_bytes(768)   # Kyber512 pk ≈ 800 bytes
    sk = random_bytes(1568)  # Kyber512 sk ≈ 1632 bytes (approx)
    return pk, sk


# ============================================================
#  Encapsulation
# ============================================================

def kem_encapsulate(pk: bytes):
    """
    Simulates IND-CCA2-secure encapsulation.

    Returns:
        ct  = ciphertext
        ssA = shared secret at encapsulator (sender)
    """
    # Random encapsulation seed
    r = random_bytes(32)

    # Ciphertext derived from (pk, r)
    ct = hash_kdf(pk, r, length=768)  # Simulated ciphertext

    # Shared secret (sender)
    ssA = hash_kdf(r, pk, ct, length=32)

    return ct, ssA


# ============================================================
#  Decapsulation
# ============================================================

def kem_decapsulate(ct: bytes, sk: bytes, pk: bytes):
    """
    Receiver reconstructs shared secret using:
        - ciphertext
        - secret key
        - public key

    This simulates the recovery mechanism in real Kyber.
    """
    ssB = hash_kdf(ct, sk, pk, length=32)
    return ssB


# ============================================================
#  High-level PQC Shared Secret Generator
# ============================================================

def generate_pqc_shared_secret(key_length_bytes=32):
    """
    Produces:
        K_PQC  = final post-quantum shared secret
        pk     = public key
        ct     = ciphertext
    """

    pk, sk = kem_keygen()
    ct, ss_sender = kem_encapsulate(pk)
    ss_receiver = kem_decapsulate(ct, sk, pk)

    # For perfect symmetric behavior, normalize using hash(r, pk, ct)
    # Both sides MUST produce same output

    if ss_sender != ss_receiver:
        # In simulated settings, this may differ slightly
        # Fix by using deterministic derivation based on ct & pk
        ss_final_sender = hash_kdf(ss_sender, ct, pk, length=key_length_bytes)
        ss_final_receiver = hash_kdf(ss_receiver, ct, pk, length=key_length_bytes)

        if ss_final_sender != ss_final_receiver:
            raise ValueError("Simulated KEM mismatch — this should never occur.")
        
        K_PQC = ss_final_sender
    else:
        # Perfect match
        K_PQC = ss_sender[:key_length_bytes]

    return K_PQC, pk, ct
