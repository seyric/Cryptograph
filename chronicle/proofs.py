"""Block proofs and chain verification.

The cryptographic checks that make the ledger worth trusting, kept out of
`chronicle.ledger` so they can be read and tested on their own:

- `build_inclusion_proof` - Merkle audit path for one entry in a block.
- `verify_chain` - walks every block, re-derives each entry hash, each Merkle
  root and each block hash, and reports the first inconsistency.

Both are pure with respect to the database: they take rows in, return data out.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from seal.merkle import MerkleTree
from seal.pqc_adapter import canonical_json
from .entry import compute_entry_hash


def build_inclusion_proof(entry_hashes: Sequence[bytes], target: bytes) -> List[Dict[str, Any]]:
    """Return the RFC 9162 style audit path for ``target`` within a block.

    Args:
        entry_hashes: Every entry hash in the block, in commit order.
        target: The entry hash being proven.

    Raises:
        ValueError: if ``target`` is not present in ``entry_hashes``.
    """
    target_index = list(entry_hashes).index(target)
    return MerkleTree(list(entry_hashes)).get_proof(target_index)


def compute_block_hash(header: Dict[str, Any]) -> bytes:
    """Recompute a block hash from its header fields."""
    return hashlib.sha3_256(canonical_json(header)).digest()


def verify_chain(blocks: Sequence[Any], entries_by_height: Dict[int, Sequence[Any]]) -> Tuple[bool, Optional[str]]:
    """Verify hash continuity, entry hashes, Merkle roots and block hashes.

    Args:
        blocks: Block rows ordered by ascending height.
        entries_by_height: Entry rows per block height, in commit order.

    Returns:
        ``(True, None)`` when the whole chain checks out, otherwise
        ``(False, reason)`` describing the first violation found.
    """
    expected_prev_hash = b"\x00" * 32
    for block in blocks:
        height = block["height"]
        if height == 0:
            expected_prev_hash = block["block_hash"]
            continue

        if block["prev_hash"] != expected_prev_hash:
            return False, f"Broken prev_hash chain at height {height}"

        entry_hashes = []
        for entry in entries_by_height.get(height, ()):
            expected = compute_entry_hash(entry["entry_type"], entry["payload"], entry["signature"])
            if expected != entry["entry_hash"]:
                return False, f"Entry record tampered at height {height}: payload hash mismatch"
            entry_hashes.append(entry["entry_hash"])

        if MerkleTree(entry_hashes).root != block["merkle_root"]:
            return False, f"Merkle root mismatch at height {height}"

        header = {
            "height": height,
            "prev_hash": block["prev_hash"].hex(),
            "merkle_root": block["merkle_root"].hex(),
            "timestamp": block["timestamp"],
            "proposer_id": block["proposer_id"],
        }
        if compute_block_hash(header) != block["block_hash"]:
            return False, f"Block hash corrupt at height {height}"

        expected_prev_hash = block["block_hash"]

    return True, None


__all__ = ["build_inclusion_proof", "compute_block_hash", "verify_chain"]
