"""Round-robin leader plus a real 2-phase commit with an enforced quorum.

Fixes two defects in the previous engine:

1. **The quorum was never enforced.** Votes were collected and then the
   ``len(collected_sigs) < 3`` branch was a bare ``pass``, so a single reachable
   node committed a block on its own signature. :meth:`BFTConsensus.propose_and_commit`
   now builds the block candidate with its real Merkle root, gathers signatures
   over :func:`chronicle.block_cert.signing_bytes`, and refuses to commit below
   :data:`QUORUM_THRESHOLD`. A single-node development cluster must set
   ``CANARY_TRAP_ALLOW_SINGLE_NODE=1`` to opt out explicitly, and the block is
   then marked uncertified so the evidence bundle can say so.

2. **Validators signed the wrong bytes.** The old code signed a candidate header
   whose ``merkle_root`` was 64 zeroes, because the real root only came into
   existence at commit time, so signatures did not commit to block contents.
   The candidate is now built first and signatures cover the real header.

Consensus rules:
- 4 nodes, tolerating f = 1 faulty; commit threshold 2f+1 = 3.
- Leader schedule: ``Leader(h) = h % 4``.
- Timestamp: median of the clocks that voted.
"""

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from seal.pqc_adapter import MLDSA65, b64_encode, b64_decode
from seal.merkle import MerkleTree
from chronicle.entry import compute_entry_hash
from chronicle.block_cert import (
    CERTIFICATE_VERSION,
    QUORUM_THRESHOLD,
    QuorumCertificate,
    block_hash_for,
    signing_bytes,
    verify_certificate,
)
from chronicle.ledger import Ledger


#: Static 4-node cluster topology.
STATIC_PEERS = {
    "NODE_01": {"url": "http://127.0.0.1:8001", "index": 1},
    "NODE_02": {"url": "http://127.0.0.1:8002", "index": 2},
    "NODE_03": {"url": "http://127.0.0.1:8003", "index": 3},
    "NODE_04": {"url": "http://127.0.0.1:8004", "index": 4},
}

#: Escape hatch for a single-node development cluster. Without it a lone node
#: cannot commit, which is the entire point of the fix.
SINGLE_NODE_ENV = "CANARY_TRAP_ALLOW_SINGLE_NODE"


class QuorumNotReached(RuntimeError):
    """Raised when a block cannot gather enough validator signatures."""


class BFTConsensus:
    """Round-robin leader, signature gathering and quorum enforcement."""

    def __init__(
        self,
        node_id: str,
        ledger: Ledger,
        validator_sk: bytes,
        validator_vk: bytes,
        peers: Optional[Dict[str, Dict[str, Any]]] = None,
        validator_keys: Optional[Dict[str, bytes]] = None,
    ):
        self.node_id = node_id
        self.ledger = ledger
        self.validator_sk = validator_sk
        self.validator_vk = validator_vk
        self.peers = peers if peers is not None else STATIC_PEERS
        #: Public keys of every validator, used to check gathered signatures.
        self.validator_keys: Dict[str, bytes] = {node_id: validator_vk}
        if validator_keys:
            self.validator_keys.update(validator_keys)

    @property
    def allow_single_node(self) -> bool:
        """Whether the explicit development escape hatch is enabled."""
        return os.environ.get(SINGLE_NODE_ENV, "").strip().lower() in {"1", "true", "yes"}

    def get_leader_for_height(self, height: int) -> str:
        """Deterministic round-robin leader: ``Leader(h) = h % 4``."""
        node_keys = sorted(self.peers.keys())
        return node_keys[height % len(node_keys)]

    def is_leader(self, target_height: int) -> bool:
        """Whether this node is the designated leader for ``target_height``."""
        return self.get_leader_for_height(target_height) == self.node_id

    def build_candidate(
        self,
        entries: List[Dict[str, Any]],
        proposer_id: str,
        timestamp: int,
    ) -> Dict[str, Any]:
        """Assemble a block candidate and the exact bytes validators must sign.

        Computing the real Merkle root before signing is what makes a signature
        commit to the block contents.

        Returns:
            The header fields, the derived block hash, the Merkle root, the
            per-entry hashes and the signing bytes.
        """
        latest = self.ledger.get_latest_block()
        height = latest["height"] + 1
        prev_hash = latest["block_hash"]

        entry_hashes = [
            compute_entry_hash(e["entry_type"], e["payload"], e["signature"]).hex()
            for e in entries
        ]
        merkle_root = MerkleTree([bytes.fromhex(h) for h in entry_hashes]).root.hex()

        return {
            "height": height,
            "prev_hash": prev_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "proposer_id": proposer_id,
            "block_hash": block_hash_for(
                height, prev_hash, merkle_root, timestamp, proposer_id
            ).hex(),
            "entry_hashes": entry_hashes,
            "signing_bytes": signing_bytes(
                height, prev_hash, merkle_root, timestamp, proposer_id
            ),
        }

    def certificate_from(
        self,
        candidate: Dict[str, Any],
        signatures: Dict[str, bytes],
    ) -> QuorumCertificate:
        """Wrap a candidate and its gathered signatures into a certificate."""
        return QuorumCertificate(
            version=CERTIFICATE_VERSION,
            height=candidate["height"],
            prev_hash=candidate["prev_hash"],
            merkle_root=candidate["merkle_root"],
            timestamp=candidate["timestamp"],
            proposer_id=candidate["proposer_id"],
            block_hash=candidate["block_hash"],
            signatures=dict(signatures),
        )

    def _request_votes(
        self,
        candidate: Dict[str, Any],
        entries: List[Dict[str, Any]],
        proposal_signature: bytes,
    ) -> Tuple[Dict[str, bytes], List[int]]:
        """Ask peers to vote, returning their signatures and clock proposals."""
        collected: Dict[str, bytes] = {}
        clocks: List[int] = [candidate["timestamp"]]

        payload = {
            "certificate_version": CERTIFICATE_VERSION,
            "height": candidate["height"],
            "prev_hash": candidate["prev_hash"],
            "merkle_root": candidate["merkle_root"],
            "timestamp": candidate["timestamp"],
            "proposer_id": candidate["proposer_id"],
            "block_hash": candidate["block_hash"],
            "signing_bytes_b64": b64_encode(candidate["signing_bytes"]),
            "proposer_sig": b64_encode(proposal_signature),
            "proposer_public_key": b64_encode(self.validator_vk),
            "entries": [
                {
                    "entry_type": e["entry_type"],
                    "payload": e["payload"],
                    "signature_b64": b64_encode(e["signature"]),
                    "signer_id": e["signer_id"],
                }
                for e in entries
            ],
        }

        for peer_id, peer in self.peers.items():
            if peer_id == self.node_id:
                continue
            try:
                request = urllib.request.Request(
                    f"{peer['url']}/api/consensus/vote",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=0.5) as response:
                    vote = json.loads(response.read().decode("utf-8"))
            except Exception:
                continue  # peer offline or slow: it simply does not vote

            if vote.get("vote") != "APPROVE":
                continue
            try:
                collected[peer_id] = b64_decode(vote["signature_b64"])
            except Exception:
                continue
            if vote.get("validator_public_key"):
                self.validator_keys.setdefault(
                    peer_id, b64_decode(vote["validator_public_key"])
                )
            if isinstance(vote.get("clock"), int):
                clocks.append(vote["clock"])

        return collected, clocks

    def propose_and_commit(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Propose a block, gather signatures, enforce the quorum, then commit.

        Args:
            entries: Entries to commit; each needs ``entry_type``, ``payload``,
                ``signature`` and ``signer_id``.

        Returns:
            The ledger commit result, plus the quorum certificate.

        Raises:
            QuorumNotReached: if fewer than ``QUORUM_THRESHOLD`` validators
                signed and the single-node escape hatch is not enabled.
        """
        if not entries:
            raise ValueError("Cannot commit an empty block (must have at least one entry)")

        now = int(time.time())
        candidate = self.build_candidate(entries, self.node_id, now)
        my_signature = MLDSA65.sign(self.validator_sk, candidate["signing_bytes"])
        signatures: Dict[str, bytes] = {self.node_id: my_signature}

        peer_sigs, clocks = self._request_votes(candidate, entries, my_signature)
        signatures.update(peer_sigs)

        # BFT median time over the clocks that actually voted.
        clocks.sort()
        timestamp = clocks[len(clocks) // 2]
        if timestamp != candidate["timestamp"]:
            # The median clock moved, so the header changes and every signature
            # collected so far is over stale bytes. Re-sign locally and re-poll
            # with the corrected timestamp.
            candidate = self.build_candidate(entries, self.node_id, timestamp)
            my_signature = MLDSA65.sign(self.validator_sk, candidate["signing_bytes"])
            signatures = {self.node_id: my_signature}
            peer_sigs, _ = self._request_votes(candidate, entries, my_signature)
            signatures.update(peer_sigs)

        certificate = self.certificate_from(candidate, signatures)
        quorum_ok, valid_ids, problems = verify_certificate(
            certificate, self.validator_keys, QUORUM_THRESHOLD
        )

        if not quorum_ok and not self.allow_single_node:
            raise QuorumNotReached(
                f"Block {candidate['height']} did not reach quorum "
                f"({len(valid_ids)}/{QUORUM_THRESHOLD} valid): " + "; ".join(problems)
            )

        commit_result = self.ledger.commit_block(
            entries=entries,
            proposer_id=self.node_id,
            validator_sigs=signatures,
            timestamp=candidate["timestamp"],
            validator_keys=self.validator_keys,
        )

        # A block committed without quorum is not evidence-grade. Say so.
        commit_result["quorum_certified"] = quorum_ok
        commit_result["validators"] = valid_ids
        commit_result["quorum_problems"] = problems
        commit_result["certificate"] = certificate.to_dict()

        self._broadcast_commit(commit_result, certificate, entries)
        return commit_result

    def _broadcast_commit(
        self,
        commit_result: Dict[str, Any],
        certificate: QuorumCertificate,
        entries: List[Dict[str, Any]],
    ) -> None:
        """Push the committed block to peers that are reachable."""
        message = {
            "height": certificate.height,
            "prev_hash": certificate.prev_hash,
            "merkle_root": certificate.merkle_root,
            "timestamp": certificate.timestamp,
            "proposer_id": certificate.proposer_id,
            "block_hash": certificate.block_hash,
            "validator_signatures": {
                vid: b64_encode(sig) for vid, sig in certificate.signatures.items()
            },
            "entries": [
                {
                    "entry_type": e["entry_type"],
                    "payload": e["payload"],
                    "signature_b64": b64_encode(e["signature"]),
                    "signer_id": e["signer_id"],
                }
                for e in entries
            ],
        }

        for peer_id, peer in self.peers.items():
            if peer_id == self.node_id:
                continue
            try:
                request = urllib.request.Request(
                    f"{peer['url']}/api/consensus/commit_block",
                    data=json.dumps(message).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=0.5):
                    continue
            except Exception:
                pass
            # Peer HTTP is down: fall back to writing its database directly so a
            # co-located development cluster still converges.
            self._sync_peer_database(peer_id, commit_result, certificate, entries)

    def _sync_peer_database(
        self,
        peer_id: str,
        commit_result: Dict[str, Any],
        certificate: QuorumCertificate,
        entries: List[Dict[str, Any]],
    ) -> None:
        """Best-effort direct-to-database replication for local clusters."""
        peer_db = f"data/{peer_id.lower()}/canarytrap_ledger.db"
        if not os.path.exists(peer_db):
            return
        try:
            peer_ledger = Ledger(db_path=peer_db, node_id=peer_id)
            if peer_ledger.get_latest_block()["height"] >= certificate.height:
                return
            peer_ledger.commit_block(
                entries=entries,
                proposer_id=certificate.proposer_id,
                validator_sigs=certificate.signatures,
                timestamp=certificate.timestamp,
                validator_keys=self.validator_keys,
            )
        except Exception:
            pass


__all__ = [
    "BFTConsensus",
    "QUORUM_THRESHOLD",
    "QuorumNotReached",
    "SINGLE_NODE_ENV",
    "STATIC_PEERS",
]
