# ==========================================================
# hybrid_key_derivation.py — Hybrid QKD + PQC key fusion
# ==========================================================

from utils.hashing import sha3_512

# ----------------------------------------------------------
# Combine QKD & PQC keys (Hybrid)
# ----------------------------------------------------------
def derive_hybrid_key(qkd_key: bytes, pqc_secret: bytes) -> bytes:
    """
    Hybrid key = SHA3-512(QKD || PQC)
    Final output: 64 bytes (512-bit)
    """
    combined = qkd_key + pqc_secret
    return sha3_512(combined)
