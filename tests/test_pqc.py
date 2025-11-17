import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import statistics

from pqc.kyber_simulator import (
    kem_keygen,
    kem_encapsulate,
    kem_decapsulate,
    generate_pqc_shared_secret
)

from hybrid_key.key_fusion import derive_hybrid_key
from qkd.qkd_simulator import generate_qkd_key


print("\n=== PQC (Simulated Kyber512) METRICS ===\n")


def test_keygen_speed(iterations=10):
    times = []
    for _ in range(iterations):
        start = time.time()
        kem_keygen()
        end = time.time()
        times.append((end-start)*1000)

    print("[METRIC] KeyGen Time")
    print("Avg: {:.4f} ms".format(statistics.mean(times)))
    print()


def test_encap_decap(iterations=10):
    enc_times = []
    dec_times = []
    fails = 0

    for _ in range(iterations):
        pk, sk = kem_keygen()

        start_enc = time.time()
        ct, ssA = kem_encapsulate(pk)
        end_enc = time.time()

        start_dec = time.time()
        ssB = kem_decapsulate(ct, sk, pk)
        end_dec = time.time()

        if ssA == ssB:
            pass
        else:
            fails += 1

        enc_times.append((end_enc-start_enc)*1000)
        dec_times.append((end_dec-start_dec)*1000)

    print("[METRIC] Encapsulation/Decapsulation")
    print("Failures:", fails)
    print("Encap Avg: {:.4f} ms".format(statistics.mean(enc_times)))
    print("Decap Avg: {:.4f} ms".format(statistics.mean(dec_times)))
    print()


def test_pqc_key_length():
    K_PQC, pk, ct = generate_pqc_shared_secret()
    print("[METRIC] PQC Shared Secret")
    print("Length:", len(K_PQC), "bytes")
    print("Public Key:", len(pk), "bytes")
    print("Ciphertext:", len(ct), "bytes")
    print()


def test_hybrid_key_derivation():
    k_qkd, qber = generate_qkd_key()
    k_pqc, _, _ = generate_pqc_shared_secret()
    hybrid = derive_hybrid_key(k_qkd, k_pqc, length_bytes=64)

    print("[METRIC] Hybrid Key")
    print("Hybrid Key Length:", len(hybrid))
    print("QBER used:", qber*100, "%")
    print()


if __name__ == "__main__":
    test_keygen_speed()
    test_encap_decap()
    test_pqc_key_length()
    test_hybrid_key_derivation()
