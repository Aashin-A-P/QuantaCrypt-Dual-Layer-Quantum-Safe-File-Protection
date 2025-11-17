import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics

from pqc.kyber_module import (
    generate_kyber_keypair,
    encapsulate_secret,
    decapsulate_secret,
    generate_pqc_shared_secret,
)

from hybrid_key.key_fusion import derive_hybrid_key
from qkd.qkd_simulator import generate_qkd_key


print("\n=== PQC (Kyber512) METRICS ===\n")


# ----------------------------------------------------------
# 1. Key Generation Speed
# ----------------------------------------------------------
def test_keygen_speed(iterations=10):
    times = []
    for _ in range(iterations):
        start = time.time()
        generate_kyber_keypair()
        end = time.time()
        times.append((end - start) * 1000)  # ms

    print("[METRIC] Kyber KeyGen Time")
    print(f"Runs: {iterations}")
    print(f"Average: {statistics.mean(times):.4f} ms")
    print(f"Min: {min(times):.4f} ms")
    print(f"Max: {max(times):.4f} ms\n")


# ----------------------------------------------------------
# 2. Encapsulation / Decapsulation Speed + Correctness
# ----------------------------------------------------------
def test_kem_encap_decap(iterations=10):
    enc_times = []
    dec_times = []
    failures = 0

    for _ in range(iterations):
        pk, sk = generate_kyber_keypair()

        start_enc = time.time()
        ct, ss_sender = encapsulate_secret(pk)
        end_enc = time.time()

        start_dec = time.time()
        ss_receiver = decapsulate_secret(ct, sk)
        end_dec = time.time()

        enc_times.append((end_enc - start_enc) * 1000)
        dec_times.append((end_dec - start_dec) * 1000)

        if ss_sender != ss_receiver:
            failures += 1

    print("[METRIC] Kyber Encapsulation / Decapsulation")
    print(f"Runs: {iterations}")
    print(f"Failures: {failures}")
    print(f"Encap Avg: {statistics.mean(enc_times):.4f} ms")
    print(f"Decap Avg: {statistics.mean(dec_times):.4f} ms\n")


# ----------------------------------------------------------
# 3. PQC Key Sizes
# ----------------------------------------------------------
def test_pqc_key_length():
    k_pqc, pk, ct = generate_pqc_shared_secret()

    print("[METRIC] PQC Shared Secret (K_PQC)")
    print(f"K_PQC Length     : {len(k_pqc)} bytes (Expected: 32 bytes)")
    print(f"Public Key Length: {len(pk)} bytes")
    print(f"Ciphertext Length: {len(ct)} bytes\n")


# ----------------------------------------------------------
# 4. Hybrid Key Derivation (QKD + PQC)
# ----------------------------------------------------------
def test_hybrid_key_derivation():
    k_qkd, qber = generate_qkd_key()
    k_pqc, _, _ = generate_pqc_shared_secret()

    hybrid = derive_hybrid_key(k_qkd, k_pqc, length_bytes=64)

    print("[METRIC] Hybrid Key Derivation")
    print(f"K_QKD Length   : {len(k_qkd)} bytes")
    print(f"K_PQC Length   : {len(k_pqc)} bytes")
    print(f"Hybrid Key Size: {len(hybrid)} bytes (Expected: 64 bytes)")
    print(f"QBER Used      : {qber * 100:.2f}%\n")


# ----------------------------------------------------------
# Run all tests
# ----------------------------------------------------------
if __name__ == "__main__":
    test_keygen_speed()
    test_kem_encap_decap()
    test_pqc_key_length()
    test_hybrid_key_derivation()
