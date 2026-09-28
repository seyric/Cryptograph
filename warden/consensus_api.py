"""HTTP endpoints for the 2-phase commit protocol.

Split out of `warden/service.py` so the wire protocol lives next to the engine
that implements it.

`/api/consensus/vote` is where a peer decides whether to sign. It re-derives the
candidate's Merkle root from the proposed entries and refuses to approve a block
whose stated root or hash does not match, so a proposer cannot ask validators to
sign contents it did not actually commit to.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter
from seal.pqc_adapter import MLDSA65, b64_encode, b64_decode
from seal.merkle import MerkleTree
from chronicle.entry import compute_entry_hash
from chronicle.block_cert import (
    CERTIFICATE_VERSION,
    block_hash_for,
    signing_bytes,
)

router = APIRouter()


def register_consensus_endpoints(app, ledger, node_id: str, validator_sk: bytes, validator_vk: bytes) -> None:
    """Attach the consensus endpoints to ``app``.

    Kept as a function rather than module-level routes so the validators can be
    injected; this keeps the module importable without a configured ledger.
    """

    @app.post("/api/consensus/vote")
    def consensus_vote(proposal: Dict[str, Any]) -> Dict[str, Any]:
        """Approve and sign a proposed block, after checking it is coherent."""
        if proposal.get("certificate_version") != CERTIFICATE_VERSION:
            return {
                "vote": "REJECT",
                "reason": f"Unsupported certificate version {proposal.get('certificate_version')!r}",
            }

        latest = ledger.get_latest_block()
        target_height = latest["height"] + 1

        if proposal.get("height") != target_height:
            return {
                "vote": "REJECT",
                "reason": f"Expected height {target_height}, got {proposal.get('height')}",
            }

        if proposal.get("prev_hash") != latest["block_hash"]:
            return {"vote": "REJECT", "reason": "Previous block hash mismatch"}

        try:
            entries = [
                {
                    "entry_type": e["entry_type"],
                    "payload": e["payload"],
                    "signature": b64_decode(e["signature_b64"]),
                    "signer_id": e["signer_id"],
                }
                for e in proposal["entries"]
            ]
        except Exception as exc:
            return {"vote": "REJECT", "reason": f"Malformed entries: {exc}"}

        # Re-derive the root from the entries rather than trusting the proposer.
        entry_hashes = [
            compute_entry_hash(e["entry_type"], e["payload"], e["signature"]) for e in entries
        ]
        derived_root = MerkleTree(entry_hashes).root.hex()
        if derived_root != proposal.get("merkle_root"):
            return {
                "vote": "REJECT",
                "reason": f"Merkle root mismatch: stated {proposal.get('merkle_root')}, derived {derived_root}",
            }

        timestamp = int(proposal.get("timestamp", time.time()))
        derived_hash = block_hash_for(
            proposal["height"],
            proposal["prev_hash"],
            derived_root,
            timestamp,
            proposal["proposer_id"],
        ).hex()
        if derived_hash != proposal.get("block_hash"):
            return {
                "vote": "REJECT",
                "reason": f"Block hash mismatch: stated {proposal.get('block_hash')}, derived {derived_hash}",
            }

        # Check the proposer's own signature over the same bytes before adding ours.
        try:
            proposer_key = b64_decode(proposal["proposer_public_key"])
            proposer_sig = b64_decode(proposal["proposer_sig"])
            signed = signing_bytes(
                proposal["height"],
                proposal["prev_hash"],
                derived_root,
                timestamp,
                proposal["proposer_id"],
            )
            if not MLDSA65.verify(proposer_key, signed, proposer_sig):
                return {"vote": "REJECT", "reason": "Proposer signature does not verify"}
        except Exception as exc:
            return {"vote": "REJECT", "reason": f"Proposer signature unusable: {exc}"}

        signature = MLDSA65.sign(validator_sk, signed)
        return {
            "vote": "APPROVE",
            "validator_id": node_id,
            "signature_b64": b64_encode(signature),
            "validator_public_key": b64_encode(validator_vk),
            "clock": int(time.time()),
        }

    @app.post("/api/consensus/commit_block")
    def consensus_commit_block(commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adopt a block that a quorum has already agreed."""
        latest = ledger.get_latest_block()
        target_height = latest["height"] + 1

        if commit_data.get("height") != target_height:
            return {
                "status": "SKIPPED",
                "reason": f"Expected height {target_height}, got {commit_data.get('height')}",
            }

        entries = [
            {
                "entry_type": e["entry_type"],
                "payload": e["payload"],
                "signature": b64_decode(e["signature_b64"]),
                "signer_id": e["signer_id"],
            }
            for e in commit_data["entries"]
        ]

        validator_sigs = {
            vid: b64_decode(sig) for vid, sig in commit_data["validator_signatures"].items()
        }

        result = ledger.commit_block(
            entries=entries,
            proposer_id=commit_data["proposer_id"],
            validator_sigs=validator_sigs,
            timestamp=commit_data.get("timestamp", int(time.time())),
        )
        return {
            "status": "COMMITTED",
            "height": result["height"],
            "block_hash": result["block_hash"],
        }


__all__ = ["register_consensus_endpoints", "router"]
