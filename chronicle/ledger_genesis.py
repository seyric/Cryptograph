"""The genesis block, defined once so every node derives the same hash.

Kept in its own module because both the ledger (which creates it) and the proof
verifier (which anchors the chain to it) need these values, and importing
``chronicle.ledger`` from ``chronicle.proofs`` would be circular.

These are deliberately fixed constants rather than wall-clock values. Every
block's ``prev_hash`` chains from the genesis block, and peers reject a proposal
whose ``prev_hash`` they do not recognise, so a node that minted its own genesis
would never reach agreement with any other node.
"""

from __future__ import annotations

import hashlib

from .block_cert import block_hash_for

#: Label hashed to produce the (empty) genesis Merkle root.
GENESIS_ROOT_LABEL = b"CANARY_TRAP_GENESIS_ROOT"

#: Fixed so that every node computes an identical genesis block hash.
GENESIS_TIMESTAMP = 0
GENESIS_PROPOSER = "GENESIS"
GENESIS_PREV_HASH = b"\x00" * 32

#: The hash every chain must start from. Precomputed so the verifier does not
#: need to re-derive it (and cannot drift from the ledger's derivation).
GENESIS_MERKLE_ROOT = hashlib.sha3_256(GENESIS_ROOT_LABEL).digest()
GENESIS_BLOCK_HASH = block_hash_for(
    0,
    GENESIS_PREV_HASH.hex(),
    GENESIS_MERKLE_ROOT.hex(),
    GENESIS_TIMESTAMP,
    GENESIS_PROPOSER,
)

__all__ = [
    "GENESIS_BLOCK_HASH",
    "GENESIS_MERKLE_ROOT",
    "GENESIS_PREV_HASH",
    "GENESIS_PROPOSER",
    "GENESIS_ROOT_LABEL",
    "GENESIS_TIMESTAMP",
]
