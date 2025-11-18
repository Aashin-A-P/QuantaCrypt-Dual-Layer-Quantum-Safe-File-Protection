import argparse
import os
from hybrid_key.key_rotation import generate_new_hybrid_bundle
from crypto_core.file_crypto import encrypt_file


def main():
    parser = argparse.ArgumentParser(description="QuantaCrypt Server")

    parser.add_argument("--input", required=True, help="Path to input file to encrypt")
    parser.add_argument("--outbox", required=True,
                        help="Folder where encrypted file will be sent")
    parser.add_argument("--shares", action="store_true",
                        help="Display generated Shamir shares")

    args = parser.parse_args()

    print("\n=== SERVER: Hybrid Key Generation ===")
    k_qkd, k_pqc, bundle = generate_new_hybrid_bundle()
    hybrid_key = bundle.hybrid_key

    print("Hybrid Key Length:", len(hybrid_key))
    print("QBER:", f"{(bundle.qber or 0)*100:.2f}%")
    print("Created:", bundle.created_at)
    print()

    # Store key for client-side retrieval (simple version)
    key_path = os.path.join(args.outbox, "shared_hybrid.key")
    with open(key_path, "wb") as f:
        f.write(hybrid_key)

    print("Hybrid key exported to:", key_path)

    # Encrypt the file
    encrypted_file_path = os.path.join(args.outbox, "encrypted.bin")
    enc_result = encrypt_file(args.input, encrypted_file_path, hybrid_key)

    print("\n=== SERVER: File Encrypted ===")
    for k, v in enc_result.items():
        print(f"{k}: {v}")

    print("\nEncrypted file sent to:", encrypted_file_path)


if __name__ == "__main__":
    main()
