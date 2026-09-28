"""Threshold Key Custody and Conditional Release Manager for CANARY TRAP Validator Nodes.

Enforces "Log Before Key":
- Releases variant key shares ONLY after a DECRYPT_REQUEST entry has been committed in a block.
- Derives the exact session codeword bit sequence c_j = PRF(K_wm, h || j).
- Releases ONLY the Shamir share corresponding to variant c_j.
- Encrypts released shares under the session's ephemeral ML-KEM public key.
"""

import os
from typing import List, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.pqc import MLKEM768, b64_encode, b64_decode
from mark.codeword import generate_codeword_bits
from vault.ledger import Ledger


class KeyCustodyManager:
    """Manages secure custody and conditional post-quantum release of Shamir key shares."""

    def __init__(self, ledger: Ledger, node_id: str, node_share_index: int, wm_master_seed: bytes):
        self.ledger = ledger
        self.node_id = node_id
        self.share_index = node_share_index
        self.wm_master_seed = wm_master_seed

    def release_shares_for_committed_session(
        self,
        doc_id: str,
        session_entry_hash_hex: str,
        ephemeral_ml_kem_pk_bytes: bytes,
        total_blocks: int
    ) -> Dict[str, Any]:
        """Verify session commitment and release encrypted Shamir shares for codeword-selected variants.
        
        Args:
            doc_id: Document identifier.
            session_entry_hash_hex: Hex SHA3-256 hash of the committed DECRYPT_REQUEST entry.
            ephemeral_ml_kem_pk_bytes: Recipient's single-use ephemeral ML-KEM encapsulation key.
            total_blocks: Number of blocks M.
            
        Returns:
            Dict matching NODE_KEY_RELEASE wire format.
        """
        # 1. Verify that entry is committed on the ledger
        entry_record = self.ledger.get_entry(session_entry_hash_hex)
        if not entry_record:
            raise PermissionError(f"Entry {session_entry_hash_hex} is not committed on the ledger")
        if entry_record["entry_type"] != "DECRYPT_REQUEST":
            raise ValueError(f"Entry {session_entry_hash_hex} is not a DECRYPT_REQUEST")

        # 2. Derive deterministic session codeword: c = PRF(K_wm, session_entry_hash)
        session_hash_bytes = bytes.fromhex(session_entry_hash_hex)
        codeword = generate_codeword_bits(self.wm_master_seed, session_hash_bytes, total_blocks)

        # 3. Retrieve this node's Shamir shares for the selected variant at each block
        released_shares = []
        for block_idx in range(total_blocks):
            chosen_variant = codeword[block_idx]
            raw_share = self.ledger.get_key_share(doc_id, block_idx, chosen_variant, share_index=self.share_index)
            if not raw_share:
                raise RuntimeError(f"Missing key share for doc {doc_id} block {block_idx} variant {chosen_variant}")
            released_shares.append({
                "block_idx": block_idx,
                "variant": chosen_variant,
                "share_index": self.share_index,
                "share_data_b64": b64_encode(raw_share)
            })

        # 4. Encapsulate shared secret to recipient's ephemeral ML-KEM key
        shared_secret, kem_ciphertext = MLKEM768.encaps(ephemeral_ml_kem_pk_bytes)

        # 5. Encrypt released shares bundle using AES-256-GCM under the ML-KEM shared secret
        import json
        bundle_bytes = json.dumps(released_shares).encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = AESGCM(shared_secret)
        encrypted_bundle = aesgcm.encrypt(nonce, bundle_bytes, associated_data=session_hash_bytes)

        return {
            "validator_id": self.node_id,
            "share_index": self.share_index,
            "doc_id": doc_id,
            "session_entry_hash": session_entry_hash_hex,
            "block_height": entry_record["block_height"],
            "ephemeral_capsule": b64_encode(kem_ciphertext),
            "nonce": b64_encode(nonce),
            "encrypted_shares_bundle": b64_encode(encrypted_bundle)
        }
