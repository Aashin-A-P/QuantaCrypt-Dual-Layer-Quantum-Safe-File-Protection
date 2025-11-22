# PQC signature for audit logs (Dilithium-style simulated)

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from pqc_signature.dilithium_sign import sign_message
from pqc_signature.dilithium_verify import verify_signature
from utils.constants import ENCODING


# ---------------------------------------------------------
# Sign an audit log entry using PQC signature
# ---------------------------------------------------------
def sign_log_entry(entry: dict, sk: bytes, pk: bytes) -> dict:
    entry_bytes = json.dumps(entry, sort_keys=True).encode(ENCODING)

    sig = sign_message(entry_bytes, sk)

    entry["signature"] = sig.hex()
    entry["public_key"] = pk.hex()

    return entry


# ---------------------------------------------------------
# Verify PQC signed audit block
# ---------------------------------------------------------
def verify_log_entry(entry: dict) -> bool:
    sig = bytes.fromhex(entry["signature"])
    pk = bytes.fromhex(entry["public_key"])

    entry_copy = dict(entry)
    del entry_copy["signature"]
    del entry_copy["public_key"]

    entry_bytes = json.dumps(entry_copy, sort_keys=True).encode(ENCODING)

    return verify_signature(entry_bytes, sig, pk)
