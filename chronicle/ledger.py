"""SQLite-backed Immutable Ledger and Key Custody Storage for CANARY TRAP Validator Nodes.

Features:
- ACID WAL-mode SQLite database
- Block header chain with Merkle tree roots and ML-DSA validator signatures
- Tamper detection: recomputes all hashes to flag unauthorized row updates or deletions
- Enrolled identities, document manifests, and Shamir key share custody
"""

import os
import json
import sqlite3
import hashlib
import time
from typing import List, Dict, Any, Optional, Tuple

from seal.merkle import MerkleTree
from seal.pqc_adapter import canonical_json, b64_encode, b64_decode
from .entry import compute_entry_hash
from .proofs import build_inclusion_proof, verify_chain
from .schema import SCHEMA_SQL
from .block_cert import (
    CERTIFICATE_VERSION,
    QuorumCertificate,
    block_hash_for,
)

from .ledger_genesis import (
    GENESIS_MERKLE_ROOT,
    GENESIS_PREV_HASH,
    GENESIS_PROPOSER,
    GENESIS_ROOT_LABEL,
    GENESIS_TIMESTAMP,
)


class Ledger:
    """Manages local blockchain state, entries, and cryptographic audit proofs."""

    def __init__(self, db_path: str, node_id: str = "NODE_01"):
        self.db_path = db_path
        self.node_id = node_id
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()
        self._ensure_genesis()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript(SCHEMA_SQL)

    def _ensure_genesis(self):
        """Create the genesis block if the ledger is empty.

        The genesis header is fully deterministic: fixed timestamp, fixed
        proposer, fixed root. Every node in a cluster must agree on the genesis
        block hash, because each block's ``prev_hash`` chains from it and peers
        reject a proposal whose ``prev_hash`` they do not recognise. Deriving the
        timestamp from the wall clock here gave each node a different genesis,
        which silently prevented any two nodes from ever reaching agreement.
        """
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM blocks;")
            if cur.fetchone()[0] == 0:
                prev_hash = GENESIS_PREV_HASH
                merkle_root = GENESIS_MERKLE_ROOT
                timestamp = GENESIS_TIMESTAMP
                proposer_id = GENESIS_PROPOSER

                block_hash = block_hash_for(
                    0, prev_hash.hex(), merkle_root.hex(), timestamp, proposer_id
                )

                cur.execute(
                    "INSERT INTO blocks (height, prev_hash, merkle_root, timestamp, proposer_id, block_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?);",
                    (0, prev_hash, merkle_root, timestamp, proposer_id, block_hash)
                )
                conn.commit()

    def get_latest_block(self) -> Dict[str, Any]:
        """Return the header of the highest block in the chain."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT 1;")
            row = cur.fetchone()
            if not row:
                raise RuntimeError("No blocks found in ledger")
            return {
                "height": row["height"],
                "prev_hash": row["prev_hash"].hex(),
                "merkle_root": row["merkle_root"].hex(),
                "timestamp": row["timestamp"],
                "proposer_id": row["proposer_id"],
                "block_hash": row["block_hash"].hex()
            }

    def commit_block(
        self,
        entries: List[Dict[str, Any]],
        proposer_id: str,
        validator_sigs: Dict[str, bytes],
        timestamp: Optional[int] = None,
        validator_keys: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, Any]:
        """Commit a new block with its transactions and validator signatures.

        Args:
            entries: Each needs ``entry_type``, ``payload``, ``signature`` and
                ``signer_id``.
            proposer_id: ID of the validator that assembled the block.
            validator_sigs: validator_id -> ML-DSA-65 signature over the block
                header (see :func:`chronicle.block_cert.signing_bytes`).
            timestamp: Optional block timestamp (defaults to now).
            validator_keys: validator_id -> public key, stored alongside each
                signature so an evidence bundle can verify the quorum offline.
                Without it the certificate is emitted but cannot be checked.
        """
        if not entries:
            raise ValueError("Cannot commit an empty block (must have at least one entry)")

        with self._get_conn() as conn:
            cur = conn.cursor()
            latest = self.get_latest_block()
            new_height = latest["height"] + 1
            prev_hash = bytes.fromhex(latest["block_hash"])
            block_time = timestamp if timestamp is not None else int(time.time())

            # Prepare canonical entry bytes and calculate entry hashes
            entry_records = []
            leaf_bytes_list = []

            for entry in entries:
                payload = entry["payload"]
                payload_str = canonical_json(payload).decode("utf-8") if isinstance(payload, dict) else str(payload)
                sig_bytes = entry["signature"]
                signer_id = entry["signer_id"]
                entry_type = entry["entry_type"]

                # Entry hash: see chronicle.entry for the single definition.
                entry_hash = compute_entry_hash(entry_type, payload_str, sig_bytes)
                leaf_bytes_list.append(entry_hash)

                entry_records.append((
                    entry_hash, new_height, entry_type, payload_str, sig_bytes, signer_id
                ))

            # Build Merkle Tree over entry hashes
            tree = MerkleTree(leaf_bytes_list)
            merkle_root = tree.root

            # Compute block hash
            block_hash = block_hash_for(
                new_height, prev_hash.hex(), merkle_root.hex(), block_time, proposer_id
            )

            # Insert block
            cur.execute(
                "INSERT INTO blocks (height, prev_hash, merkle_root, timestamp, proposer_id, block_hash) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (new_height, prev_hash, merkle_root, block_time, proposer_id, block_hash)
            )

            # Insert entries
            cur.executemany(
                "INSERT INTO entries (entry_hash, block_height, entry_type, payload, signature, signer_id) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                entry_records
            )

            # Insert validator signatures and their public keys
            for val_id, sig in validator_sigs.items():
                cur.execute(
                    "INSERT INTO block_signatures "
                    "(block_height, validator_id, signature, public_key) "
                    "VALUES (?, ?, ?, ?);",
                    (new_height, val_id, sig, (validator_keys or {}).get(val_id))
                )

            # Update specialized state tables (enrolled_identities, manifests)
            for entry_hash, _, entry_type, payload_str, sig_bytes, _ in entry_records:
                try:
                    p_dict = json.loads(payload_str)
                except Exception:
                    continue

                if entry_type == "ENROLL":
                    cur.execute(
                        "INSERT OR REPLACE INTO enrolled_identities "
                        "(recipient_id, ml_kem_public_key, ml_dsa_public_key, enrolled_at) "
                        "VALUES (?, ?, ?, ?);",
                        (
                            p_dict["recipient_id"],
                            b64_decode(p_dict["ml_kem_public_key"]),
                            b64_decode(p_dict["ml_dsa_public_key"]),
                            p_dict.get("timestamp", block_time)
                        )
                    )
                elif entry_type == "MANIFEST":
                    cur.execute(
                        "INSERT OR REPLACE INTO manifests "
                        "(doc_id, container_hash, authorized_recipients, total_blocks, expiry, quota, manifest_signature) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        (
                            p_dict["doc_id"],
                            bytes.fromhex(p_dict["container_hash"]),
                            json.dumps(p_dict["authorized_recipients"]),
                            p_dict["total_blocks"],
                            p_dict["expiry"],
                            p_dict["quota_per_recipient"],
                            sig_bytes
                        )
                    )

            conn.commit()

            certificate = QuorumCertificate(
                version=CERTIFICATE_VERSION,
                height=new_height,
                prev_hash=prev_hash.hex(),
                merkle_root=merkle_root.hex(),
                timestamp=block_time,
                proposer_id=proposer_id,
                block_hash=block_hash.hex(),
                signatures=dict(validator_sigs),
            )

            return {
                "height": new_height,
                "block_hash": block_hash.hex(),
                "merkle_root": merkle_root.hex(),
                "total_entries": len(entries),
                "entry_hashes": [r[0].hex() for r in entry_records],
                "certificate": certificate.to_dict(),
            }

    def store_key_shares(self, doc_id: str, shares_records: List[Dict[str, Any]]):
        """Store encrypted Shamir key shares for a document."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            rows = [
                (
                    doc_id,
                    s["block_idx"],
                    s["variant"],
                    s["share_index"],
                    b64_decode(s["encrypted_share"]) if isinstance(s["encrypted_share"], str) else s["encrypted_share"]
                )
                for s in shares_records
            ]
            cur.executemany(
                "INSERT OR REPLACE INTO key_shares "
                "(doc_id, block_idx, variant, share_index, encrypted_share) "
                "VALUES (?, ?, ?, ?, ?);",
                rows
            )
            conn.commit()

    def get_key_share(self, doc_id: str, block_idx: int, variant: int, share_index: Optional[int] = None) -> Optional[bytes]:
        """Retrieve stored key share for given document block, variant, and share index."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            if share_index is not None:
                cur.execute(
                    "SELECT encrypted_share FROM key_shares "
                    "WHERE doc_id = ? AND block_idx = ? AND variant = ? AND share_index = ? LIMIT 1;",
                    (doc_id, block_idx, variant, share_index)
                )
            else:
                cur.execute(
                    "SELECT encrypted_share FROM key_shares "
                    "WHERE doc_id = ? AND block_idx = ? AND variant = ? LIMIT 1;",
                    (doc_id, block_idx, variant)
                )
            row = cur.fetchone()
            return row["encrypted_share"] if row else None

    def get_entry(self, entry_hash_hex: str) -> Optional[Dict[str, Any]]:
        """Retrieve entry and its block context."""
        entry_hash = bytes.fromhex(entry_hash_hex)
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT e.*, b.block_hash, b.timestamp as block_timestamp, b.merkle_root "
                "FROM entries e JOIN blocks b ON e.block_height = b.height "
                "WHERE e.entry_hash = ?;",
                (entry_hash,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "entry_hash": row["entry_hash"].hex(),
                "block_height": row["block_height"],
                "block_hash": row["block_hash"].hex(),
                "block_timestamp": row["block_timestamp"],
                "merkle_root": row["merkle_root"].hex(),
                "entry_type": row["entry_type"],
                "payload": json.loads(row["payload"]),
                "signature": b64_encode(row["signature"]),
                "signer_id": row["signer_id"]
            }

    def get_merkle_proof(self, entry_hash_hex: str) -> Optional[Dict[str, Any]]:
        """Generate Merkle audit inclusion proof for an entry."""
        entry_hash = bytes.fromhex(entry_hash_hex)
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT block_height FROM entries WHERE entry_hash = ?;", (entry_hash,))
            row = cur.fetchone()
            if not row:
                return None
            height = row["block_height"]

            # Load all entries in that block in deterministic order
            cur.execute("SELECT entry_hash FROM entries WHERE block_height = ? ORDER BY rowid ASC;", (height,))
            all_entries = [r["entry_hash"] for r in cur.fetchall()]

            proof = build_inclusion_proof(all_entries, entry_hash)

            # Get block header and signatures
            cur.execute("SELECT * FROM blocks WHERE height = ?;", (height,))
            b_row = cur.fetchone()
            cur.execute("SELECT * FROM block_signatures WHERE block_height = ?;", (height,))
            sigs = []
            for row in cur.fetchall():
                item = {
                    "validator_id": row["validator_id"],
                    "signature": b64_encode(row["signature"]),
                }
                # Carry the public key so an offline verifier can check the
                # signature instead of taking the count on trust.
                if row["public_key"] is not None:
                    item["public_key"] = b64_encode(row["public_key"])
                sigs.append(item)

            return {
                "block_height": height,
                "block_hash": b_row["block_hash"].hex(),
                "merkle_root": b_row["merkle_root"].hex(),
                "prev_hash": b_row["prev_hash"].hex(),
                "proposer_id": b_row["proposer_id"],
                "block_timestamp": b_row["timestamp"],
                "proof": [{"position": p["position"], "hash": p["hash"].hex()} for p in proof],
                "validator_signatures": sigs,
            }

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Scan entire chain to verify hash continuity and Merkle root correctness."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM blocks ORDER BY height ASC;")
            blocks = cur.fetchall()
            entries_by_height: Dict[int, List[Any]] = {}
            for block in blocks:
                height = block["height"]
                if height == 0:
                    continue
                cur.execute(
                    "SELECT entry_hash, entry_type, payload, signature FROM entries "
                    "WHERE block_height = ? ORDER BY rowid ASC;",
                    (height,),
                )
                entries_by_height[height] = cur.fetchall()

        return verify_chain(blocks, entries_by_height)
