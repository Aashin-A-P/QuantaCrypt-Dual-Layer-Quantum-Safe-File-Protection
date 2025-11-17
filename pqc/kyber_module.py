import hashlib
from kyber import Kyber512


def generate_kyber_keypair():
    """
    Generate Kyber512 keypair using kyber-py.
    Returns: (public_key, secret_key)
    """
    kyber = Kyber512()
    pk, sk = kyber.keygen()
    return pk, sk


def encapsulate_secret(public_key: bytes):
    """
    Encapsulate a shared secret using Kyber512.
    Returns: (ciphertext, shared_secret_sender)
    """
    kyber = Kyber512()
    ct, ss_sender = kyber.encrypt(public_key)
    return ct, ss_sender


def decapsulate_secret(ciphertext: bytes, secret_key: bytes):
    """
    Decapsulate ciphertext using Kyber512.
    Returns: shared_secret_receiver
    """
    kyber = Kyber512()
    ss_receiver = kyber.decrypt(ciphertext, secret_key)
    return ss_receiver


def generate_pqc_shared_secret(key_length_bytes=32):
    """
    High-level helper:
    - Generate Kyber keypair
    - Encapsulate secret
    - Decapsulate
    - Derive final K_PQC via SHA3-512

    Returns:
        (K_PQC, public_key, ciphertext)
    """
    pk, sk = generate_kyber_keypair()
    ct, ss_sender = encapsulate_secret(pk)
    ss_receiver = decapsulate_secret(ct, sk)

    if ss_sender != ss_receiver:
        raise ValueError("Kyber shared secrets mismatch!")

    # Normalize to 32 bytes (256-bit)
    digest = hashlib.sha3_512(ss_sender).digest()
    K_PQC = digest[:key_length_bytes]

    return K_PQC, pk, ct
