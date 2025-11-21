from dataclasses import dataclass
from typing import List, Literal, Tuple

from .secret_sharing import make_shamir_shares, reconstruct_shamir_secret

# Two channels: quantum (QKD) and classical (PQC)
Channel = Literal["qkd_channel", "pqc_channel"]

@dataclass
class ShareRecord:
    """
    Wrapper for a single Shamir share with its assigned channel.
    """
    index: int     # 1..n
    x: int         # share x-coordinate
    data: bytes    # share y as bytes
    channel: Channel   # "qkd_channel" or "pqc_channel"

def distribute_shares(
    hybrid_key: bytes,
    n: int,
    k: int
) -> List[ShareRecord]:
    """
    Split hybrid_key into n Shamir shares with threshold k,
    and assign:
        - first n/2 shares → QKD channel
        - last  n/2 shares → PQC channel

    This enforces dual-channel threshold security.
    """

    if n % 2 != 0:
        raise ValueError("n must be even for clean dual-channel distribution")

    # Base Shamir splitting
    raw_shares = make_shamir_shares(hybrid_key, n=n, k=k)

    half = n // 2
    records: List[ShareRecord] = []

    for idx, (x, y) in enumerate(raw_shares):
        if idx < half:
            channel: Channel = "qkd_channel"
        else:
            channel = "pqc_channel"

        records.append(
            ShareRecord(
                index=idx + 1,
                x=x,
                data=y,
                channel=channel,
            )
        )

    return records

def reconstruct_from_records(
    records: List[ShareRecord],
    k: int,
    out_length: int
) -> bytes:
    """
    Reconstruct the hybrid key using any k valid ShareRecord entries.

    Caller MUST ensure:
      - records only contain shares from uncompromised channels.
      - len(records) >= k
    """
    if len(records) < k:
        raise ValueError(
            f"Need at least {k} valid shares to reconstruct key "
            f"(received {len(records)})"
        )

    # Take exactly k shares
    selected: List[ShareRecord] = records[:k]

    # Convert to (x, y_bytes) for core Shamir
    basic_shares: List[Tuple[int, bytes]] = [
        (r.x, r.data) for r in selected
    ]

    return reconstruct_shamir_secret(
        basic_shares,
        k=k,
        out_length=out_length,
    )
