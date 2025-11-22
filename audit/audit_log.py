# audit_log.py
# Tamper-evident PQC-signed + Blockchain-anchored audit log

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import hashlib

from utils.constants import AUDIT_LOG_FILE
from audit.audit_signer import sign_log_entry
from audit.pychain_anchor import anchor_to_blockchain


# ---------------------------------------------------------
# Hash entry
# ---------------------------------------------------------
def hash_entry(entry: dict) -> str:
    entry_bytes = json.dumps(entry, sort_keys=True).encode("utf-8")
    return hashlib.sha3_256(entry_bytes).hexdigest()


# ---------------------------------------------------------
# Get previous hash for chaining
# ---------------------------------------------------------
def get_last_log_hash() -> str:
    if not os.path.exists(AUDIT_LOG_FILE):
        return "0" * 64  # Genesis hash

    with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        return "0" * 64

    last = json.loads(lines[-1])
    return last["entry_hash"]


# ---------------------------------------------------------
# Create entry
# ---------------------------------------------------------
def create_log_entry(event_type: str, details: dict) -> dict:
    entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "details": details,
        "prev_hash": get_last_log_hash()
    }
    entry["entry_hash"] = hash_entry(entry)
    return entry


# ---------------------------------------------------------
# Append entry + optional PQC signature + blockchain anchor
# ---------------------------------------------------------
def append_log(entry: dict, sk: bytes = None, pk: bytes = None):
    if sk and pk:
        entry = sign_log_entry(entry, sk, pk)

    # Append to log
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # Anchor to Bitcoin blockchain
    anchor_to_blockchain()

    print("[AUDIT] Entry appended + anchored.")
