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

from core.merkle import MerkleTree, hash_leaf
from core.pqc import canonical_json, b64_encode, b64_decode


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
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                prev_hash BLOB NOT NULL,
                merkle_root BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                proposer_id TEXT NOT NULL,
                block_hash BLOB NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS entries (
                entry_hash BLOB PRIMARY KEY,
                block_height INTEGER NOT NULL REFERENCES blocks(height),
                entry_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                signature BLOB NOT NULL,
                signer_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS block_signatures (
                block_height INTEGER NOT NULL REFERENCES blocks(height),
                validator_id TEXT NOT NULL,
                signature BLOB NOT NULL,
                PRIMARY KEY (block_height, validator_id)
            );

            CREATE TABLE IF NOT EXISTS enrolled_identities (
                recipient_id TEXT PRIMARY KEY,
                ml_kem_public_key BLOB NOT NULL,
                ml_dsa_public_key BLOB NOT NULL,
                enrolled_at INTEGER NOT NULL,
                is_revoked INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS manifests (
                doc_id TEXT PRIMARY KEY,
                container_hash BLOB NOT NULL,
                authorized_recipients TEXT NOT NULL,
                total_blocks INTEGER NOT NULL,
                expiry INTEGER NOT NULL,
                quota INTEGER NOT NULL,
                manifest_signature BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_shares (
                doc_id TEXT NOT NULL,
                block_idx INTEGER NOT NULL,
                variant INTEGER NOT NULL,
                share_index INTEGER NOT NULL,
                encrypted_share BLOB NOT NULL,
                PRIMARY KEY (doc_id, block_idx, variant, share_index)
            );
            """)

    def _ensure_genesis(self):
        """Commit Genesis Block (Height 0) if ledger is newly created."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM blocks;")
            if cur.fetchone()[0] == 0:
                prev_hash = b"\x00" * 32
                merkle_root = hashlib.sha3_256(b"CANARY_TRAP_GENESIS_ROOT").digest()
                timestamp = int(time.time())
                proposer_id = "GENESIS"
                
                header_data = {
                    "height": 0,
                    "prev_hash": prev_hash.hex(),
                    "merkle_root": merkle_root.hex(),
                    "timestamp": timestamp,
                    "proposer_id": proposer_id
                }
                block_hash = hashlib.sha3_256(canonical_json(header_data)).digest()

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
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """Commit a new block with its transactions and validator signatures.
        
        Args:
            entries: List of dicts with:
                - entry_type: str (ENROLL, MANIFEST, DECRYPT_REQUEST, etc.)
                - payload: dict or str
                - signature: bytes (ML-DSA signature)
                - signer_id: str
            proposer_id: ID of validator proposing the block.
            validator_sigs: Dict mapping validator_id -> ML-DSA-65 signature over block_hash.
            timestamp: Optional block timestamp (defaults to current time).
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

                # Entry hash: SHA3-256(0x00 || entry_type || payload_str || sig_bytes)
                hasher = hashlib.sha3_256()
                hasher.update(b"\x00")
                hasher.update(entry_type.encode("utf-8"))
                hasher.update(payload_str.encode("utf-8"))
                hasher.update(sig_bytes)
                entry_hash = hasher.digest()

                leaf_bytes = hasher.digest()
                leaf_bytes_list.append(leaf_bytes)

                entry_records.append((
                    entry_hash, new_height, entry_type, payload_str, sig_bytes, signer_id
                ))

            # Build Merkle Tree over entry hashes
            tree = MerkleTree(leaf_bytes_list)
            merkle_root = tree.root

            # Compute block hash
            header_dict = {
                "height": new_height,
                "prev_hash": prev_hash.hex(),
                "merkle_root": merkle_root.hex(),
                "timestamp": block_time,
                "proposer_id": proposer_id
            }
            block_hash = hashlib.sha3_256(canonical_json(header_dict)).digest()

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

            # Insert validator signatures
            for val_id, sig in validator_sigs.items():
                cur.execute(
                    "INSERT INTO block_signatures (block_height, validator_id, signature) "
                    "VALUES (?, ?, ?);",
                    (new_height, val_id, sig)
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

            return {
                "height": new_height,
                "block_hash": block_hash.hex(),
                "merkle_root": merkle_root.hex(),
                "total_entries": len(entries),
                "entry_hashes": [r[0].hex() for r in entry_records]
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

            tree = MerkleTree(all_entries)
            target_idx = all_entries.index(entry_hash)
            proof = tree.get_proof(target_idx)

            # Get block header and signatures
            cur.execute("SELECT * FROM blocks WHERE height = ?;", (height,))
            b_row = cur.fetchone()
            cur.execute("SELECT * FROM block_signatures WHERE block_height = ?;", (height,))
            sigs = [{"validator_id": r["validator_id"], "signature": b64_encode(r["signature"])} for r in cur.fetchall()]

            return {
                "block_height": height,
                "block_hash": b_row["block_hash"].hex(),
                "merkle_root": b_row["merkle_root"].hex(),
                "proof": [{"position": p["position"], "hash": p["hash"].hex()} for p in proof],
                "validator_signatures": sigs
            }

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Scan entire chain to verify hash continuity and Merkle root correctness."""
        with self._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM blocks ORDER BY height ASC;")
            blocks = cur.fetchall()

            expected_prev_hash = b"\x00" * 32
            for b in blocks:
                h = b["height"]
                if h == 0:
                    expected_prev_hash = b["block_hash"]
                    continue

                if b["prev_hash"] != expected_prev_hash:
                    return False, f"Broken prev_hash chain at height {h}"

                # Verify each entry payload and signature against its entry_hash
                cur.execute("SELECT entry_hash, entry_type, payload, signature FROM entries WHERE block_height = ? ORDER BY rowid ASC;", (h,))
                entry_rows = cur.fetchall()
                entry_hashes = []
                for er in entry_rows:
                    hasher = hashlib.sha3_256()
                    hasher.update(b"\x00")
                    hasher.update(er["entry_type"].encode("utf-8"))
                    hasher.update(er["payload"].encode("utf-8"))
                    hasher.update(er["signature"])
                    expected_eh = hasher.digest()
                    if expected_eh != er["entry_hash"]:
                        return False, f"Entry record tampered at height {h}: payload hash mismatch"
                    entry_hashes.append(er["entry_hash"])

                # Reconstruct Merkle tree from entries
                tree = MerkleTree(entry_hashes)
                if tree.root != b["merkle_root"]:
                    return False, f"Merkle root mismatch at height {h}"

                # Recompute block hash
                header = {
                    "height": h,
                    "prev_hash": b["prev_hash"].hex(),
                    "merkle_root": b["merkle_root"].hex(),
                    "timestamp": b["timestamp"],
                    "proposer_id": b["proposer_id"]
                }
                computed_h = hashlib.sha3_256(canonical_json(header)).digest()
                if computed_h != b["block_hash"]:
                    return False, f"Block hash corrupt at height {h}"

                expected_prev_hash = b["block_hash"]

            return True, None
