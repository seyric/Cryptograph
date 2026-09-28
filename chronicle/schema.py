"""SQLite schema for the provenance ledger.

Kept apart from `chronicle.ledger` so the table definitions can be read, diffed
and migrated in one place. `SCHEMA_SQL` is applied verbatim on every open; all
statements are `IF NOT EXISTS`, so applying it to an existing database is a
no-op and preserves stored data.

Shares are stored **encrypted at rest**: `warden.custody.KeyCustodyManager` wraps
each share with AES-256-GCM under a per-node key before it is written here, so
`key_shares.encrypted_share` holds `nonce || AES-GCM(nonce, share)` bound to
``doc_id:block_idx:variant`` as associated data. Reading a row without that
node's key yields ciphertext, not a usable Shamir share.
"""

from __future__ import annotations

SCHEMA_SQL = """
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
                public_key BLOB,
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
            """

__all__ = ["SCHEMA_SQL"]
