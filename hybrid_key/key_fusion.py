import hashlib


def derive_hybrid_key(k_qkd: bytes, k_pqc: bytes, length_bytes: int = 64) -> bytes:
    """
    Derive a hybrid key by hashing the concatenation of:
        K_QKD || K_PQC  using SHA3-512.

    length_bytes:
        How many bytes to return from the hash output.
        32 bytes  = 256-bit key
        64 bytes  = 512-bit key (default)

    Returns:
        hybrid_key: bytes
    """
    if not isinstance(k_qkd, (bytes, bytearray)) or not isinstance(k_pqc, (bytes, bytearray)):
        raise TypeError("k_qkd and k_pqc must be bytes-like objects")

    digest = hashlib.sha3_512(k_qkd + k_pqc).digest()
    return digest[:length_bytes]
