import argparse
import os
from crypto_core.file_crypto import decrypt_file


def main():
    parser = argparse.ArgumentParser(description="QuantaCrypt Client")

    parser.add_argument("--inbox", required=True,
                        help="Folder where server has placed encrypted file + key")
    parser.add_argument("--output", required=True,
                        help="Path to write decrypted output file")

    args = parser.parse_args()

    encrypted_path = os.path.join(args.inbox, "encrypted.bin")
    key_path = os.path.join(args.inbox, "shared_hybrid.key")

    print("\n=== CLIENT: Starting Decryption ===")

    if not os.path.exists(encrypted_path):
        print("Error: encrypted.bin not found in inbox")
        return

    if not os.path.exists(key_path):
        print("Error: shared_hybrid.key not found in inbox")
        return

    # Load hybrid key
    with open(key_path, "rb") as f:
        hybrid_key = f.read()

    print("Hybrid key loaded ({} bytes)".format(len(hybrid_key)))

    # Decrypt
    dec_result = decrypt_file(encrypted_path, args.output, hybrid_key)

    print("\n=== CLIENT: File Decrypted ===")
    for k, v in dec_result.items():
        print(f"{k}: {v}")

    print("\nDecrypted file saved to:", args.output)


if __name__ == "__main__":
    main()
