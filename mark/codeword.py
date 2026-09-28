"""Codeword generation using deterministic HMAC-SHA3-256 PRF.

Maps a session's committed entry hash and master watermark seed into an M-bit
pseudorandom codeword c in {0, 1}^M.
"""

import hashlib
import hmac
from typing import List


def generate_codeword_bits(wm_seed: bytes, session_hash: bytes, total_blocks: int) -> List[int]:
    """Generate an M-bit deterministic session codeword from master seed and session entry hash.
    
    Args:
        wm_seed: 32-byte secret document watermark master key.
        session_hash: 32-byte SHA3-256 hash of the committed DECRYPT_REQUEST entry.
        total_blocks: Total number of variation blocks M.
        
    Returns:
        List of integers in {0, 1} of length total_blocks.
    """
    if not isinstance(wm_seed, (bytes, bytearray)):
        raise TypeError("wm_seed must be bytes")
    if not isinstance(session_hash, (bytes, bytearray)) or len(session_hash) != 32:
        raise ValueError("session_hash must be a 32-byte hash")
    if total_blocks <= 0:
        raise ValueError("total_blocks must be positive")

    codeword = []
    for block_idx in range(total_blocks):
        # PRF input: session_hash || block_idx (4 bytes big-endian)
        msg = session_hash + block_idx.to_bytes(4, byteorder="big")
        prf_output = hmac.new(wm_seed, msg, hashlib.sha3_256).digest()
        bit = prf_output[0] & 1
        codeword.append(bit)

    return codeword
