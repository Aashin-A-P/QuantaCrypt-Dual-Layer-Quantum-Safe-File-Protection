import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import json
import time
import requests

from utils.constants import AUDIT_LOG_FILE

ANCHOR_FILE = "audit_anchor.json"


# Compute SHA3 hash of the audit log
def compute_audit_hash():
    if not os.path.exists(AUDIT_LOG_FILE):
        return None

    with open(AUDIT_LOG_FILE, "rb") as f:
        digest = hashlib.sha3_256(f.read()).hexdigest()

    return digest


# Fetch the latest block from Bitcoin Mainnet
def get_latest_block():
    url = "https://mempool.space/api/blocks"
    try:
        blocks = requests.get(url, timeout=20).json()
        return blocks[0]  # newest block
    except:
        return None

def anchor_to_blockchain():
    log_hash = compute_audit_hash()
    if log_hash is None:
        print("[ANCHOR] No audit.log found.")
        return

    blk = get_latest_block()
    if blk is None:
        print("[ANCHOR] Could not fetch Bitcoin block.")
        return

    anchor_data = {
        "timestamp": time.time(),
        "audit_log_hash": log_hash,
        "block_height": blk["height"],
        "block_hash": blk["id"],
        "tx_count": blk["tx_count"],
        "time": blk["timestamp"]
    }

    # Save anchor file
    with open(ANCHOR_FILE, "w", encoding="utf-8") as f:
        json.dump(anchor_data, f, indent=4)

    print(f"[ANCHOR] Audit anchored to Bitcoin block {blk['height']} ({blk['id'][:12]}...)")

    return anchor_data

def verify_anchor():
    if not os.path.exists(ANCHOR_FILE):
        return {"status": "NO_ANCHOR"}

    with open(ANCHOR_FILE, "r", encoding="utf-8") as f:
        anchor = json.load(f)

    current_hash = compute_audit_hash()

    if current_hash != anchor["audit_log_hash"]:
        return {
            "status": "TAMPERED",
            "expected": anchor["audit_log_hash"],
            "actual": current_hash
        }

    # Fetch current block of same height
    blk_url = f"https://mempool.space/api/block-height/{anchor['block_height']}"
    blk_hash_now = requests.get(blk_url).text.strip()

    if blk_hash_now != anchor["block_hash"]:
        return {
            "status": "CHAIN_MISMATCH",
            "expected": anchor["block_hash"],
            "actual": blk_hash_now
        }

    return {
        "status": "VALID",
        "block_height": anchor["block_height"],
        "block_hash": anchor["block_hash"],
        "audit_hash": anchor["audit_log_hash"],
        "timestamp": anchor["timestamp"]
    }
