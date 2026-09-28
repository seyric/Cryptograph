"""Shared test fixtures: a real in-process validator quorum.

Tests that commit blocks must produce a genuine quorum certificate, because the
offline verifier now rejects any validator signature it cannot check. Committing
with a placeholder signature no longer produces a valid bundle, so these helpers
build an actual 3-of-4 quorum: real ML-DSA-65 keys, signatures over the real
block header, and public keys stored alongside them.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from seal.pqc_adapter import MLDSA65
from chronicle.ledger import Ledger
from chronicle.block_cert import (
    CERTIFICATE_VERSION,
    QUORUM_THRESHOLD,
    QuorumCertificate,
    block_hash_for,
    signing_bytes,
)
from seal.merkle import MerkleTree
from chronicle.entry import compute_entry_hash

VALIDATOR_IDS = ["VAL_NODE_01", "VAL_NODE_02", "VAL_NODE_03", "VAL_NODE_04"]


class QuorumFixture:
    """A set of validator keys able to sign blocks with a real quorum."""

    def __init__(self, count: int = QUORUM_THRESHOLD):
        self.keys: Dict[str, Dict[str, bytes]] = {}
        for validator_id in VALIDATOR_IDS[:count]:
            vk, sk = MLDSA65.keygen()
            self.keys[validator_id] = {"vk": vk, "sk": sk}

    @property
    def validator_keys(self) -> Dict[str, bytes]:
        return {vid: material["vk"] for vid, material in self.keys.items()}

    def commit(self, ledger: Ledger, entries: List[Dict[str, Any]], proposer_id: str | None = None):
        """Assemble a block and commit it with a genuine quorum certificate."""
        proposer_id = proposer_id or next(iter(self.keys))
        latest = ledger.get_latest_block()
        height = latest["height"] + 1
        prev_hash = latest["block_hash"]
        timestamp = latest["timestamp"] + 1  # deterministic and monotonic

        entry_hashes = [
            compute_entry_hash(e["entry_type"], e["payload"], e["signature"]) for e in entries
        ]
        merkle_root = MerkleTree(entry_hashes).root.hex()

        signed = signing_bytes(height, prev_hash, merkle_root, timestamp, proposer_id)
        signatures = {
            vid: MLDSA65.sign(material["sk"], signed)
            for vid, material in self.keys.items()
        }

        return ledger.commit_block(
            entries=entries,
            proposer_id=proposer_id,
            validator_sigs=signatures,
            timestamp=timestamp,
            validator_keys=self.validator_keys,
        )


__all__ = ["QuorumFixture", "VALIDATOR_IDS"]
