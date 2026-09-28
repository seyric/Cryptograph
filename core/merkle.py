"""Hand-rolled Binary Merkle Tree implementation using SHA3-256.

Implements strict cryptographic domain separation to prevent second-preimage attacks:
- Leaf Hash: SHA3-256(0x00 || leaf_data)
- Internal Node Hash: SHA3-256(0x01 || left_child || right_child)

Audit proofs match RFC 6962 / RFC 9162 conventions:
- Inclusion proof yields a list of (position, sibling_hash) elements.
- Verification requires only the target leaf, proof path, and expected root hash.
"""

import hashlib
from typing import List, Dict, Any, Optional


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """Compute domain-separated leaf hash: SHA3-256(0x00 || data)."""
    return hashlib.sha3_256(LEAF_PREFIX + data).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """Compute domain-separated internal node hash: SHA3-256(0x01 || left || right)."""
    return hashlib.sha3_256(NODE_PREFIX + left + right).digest()


class MerkleTree:
    """Binary Merkle Tree for immutable ledger block commits."""

    def __init__(self, leaves: Optional[List[bytes]] = None):
        self.leaves: List[bytes] = []
        self.levels: List[List[bytes]] = []
        if leaves:
            for leaf in leaves:
                self.add_leaf(leaf)
            self.build()

    def add_leaf(self, data: bytes) -> int:
        """Add raw leaf data and return its index."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Leaf data must be bytes or bytearray")
        idx = len(self.leaves)
        self.leaves.append(bytes(data))
        return idx

    def build(self) -> bytes:
        """Construct the Merkle tree from current leaves and return the root hash."""
        if not self.leaves:
            # Empty tree root is SHA3-256 of empty string
            empty_root = hashlib.sha3_256(b"").digest()
            self.levels = [[empty_root]]
            return empty_root

        # Level 0: Leaf hashes
        current_level = [hash_leaf(leaf) for leaf in self.leaves]
        self.levels = [current_level]

        # Build tree upwards
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    parent = hash_children(left, right)
                else:
                    # Odd node: promote to next level without hashing
                    parent = left
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

        return self.root

    @property
    def root(self) -> bytes:
        """Return the root hash of the tree."""
        if not self.levels:
            self.build()
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> List[Dict[str, Any]]:
        """Generate an audit inclusion proof for the leaf at leaf_index.
        
        Returns:
            List of dicts: [{"position": "left" | "right", "hash": bytes}, ...]
        """
        if not self.levels or not self.leaves:
            self.build()

        if not (0 <= leaf_index < len(self.leaves)):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self.leaves) - 1}]")

        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            is_right_child = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right_child else idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
                proof.append({
                    "position": "left" if is_right_child else "right",
                    "hash": sibling_hash
                })
            # If no sibling (odd last node), nothing is added at this level; node was promoted directly.
            idx //= 2

        return proof


def verify_merkle_proof(leaf_data: bytes, proof: List[Dict[str, Any]], expected_root: bytes) -> bool:
    """Verify an inclusion proof against an expected Merkle root without the full tree.
    
    Args:
        leaf_data: Raw bytes of the leaf to verify.
        proof: List of dicts with 'position' ('left' or 'right') and 'hash' (bytes).
        expected_root: Expected 32-byte Merkle root hash.
        
    Returns:
        True if the proof validly chains to expected_root, False otherwise.
    """
    current_hash = hash_leaf(leaf_data)

    for step in proof:
        sibling = step["hash"]
        pos = step["position"]

        if pos == "right":
            current_hash = hash_children(current_hash, sibling)
        elif pos == "left":
            current_hash = hash_children(sibling, current_hash)
        else:
            raise ValueError(f"Invalid proof position: {pos}")

    return current_hash == expected_root
