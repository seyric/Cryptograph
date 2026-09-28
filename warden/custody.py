"""Threshold key custody and conditional release for validator nodes.

Enforces "log before key": the Shamir shares for the variants selected by a
session's codeword are released only after that session's ``DECRYPT_REQUEST``
is committed to the ledger.

Shares are now held **encrypted at rest**. Each node wraps every share with
AES-256-GCM under a locally generated 32-byte key that never leaves the node, so
a stolen database file yields ciphertext rather than directly usable shares. The
key is created on first use and stored beside the node's own database.
"""

import json
import os
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from seal.pqc_adapter import MLKEM768, b64_encode, b64_decode
from dye.codeword import generate_codeword_bits
from chronicle.ledger import Ledger

#: Filename of a node's share-wrapping key, inside that node's data directory.
SHARE_KEY_FILENAME = "share_wrap_key.bin"


def load_or_create_share_key(node_dir: str) -> bytes:
    """Return this node's share-wrapping key, generating one on first use.

    Losing this key means losing access to the node's stored shares, which is
    the correct failure mode: the shares become unrecoverable rather than
    readable to anyone who obtains the database.
    """
    os.makedirs(node_dir, exist_ok=True)
    path = os.path.join(node_dir, SHARE_KEY_FILENAME)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            key = handle.read()
        if len(key) == 32:
            return key
    key = os.urandom(32)
    with open(path, "wb") as handle:
        handle.write(key)
    return key


class KeyCustodyManager:
    """Secure custody and conditional post-quantum release of Shamir shares."""

    def __init__(
        self,
        ledger: Ledger,
        node_id: str,
        node_share_index: int,
        wm_master_seed: bytes,
        share_wrap_key: Optional[bytes] = None,
    ):
        self.ledger = ledger
        self.node_id = node_id
        self.share_index = node_share_index
        self.wm_master_seed = wm_master_seed
        if share_wrap_key is None:
            share_wrap_key = load_or_create_share_key(
                os.path.dirname(os.path.abspath(ledger.db_path))
            )
        self._share_wrap_key = share_wrap_key

    @staticmethod
    def share_context(doc_id: str, block_idx: int, variant: int) -> bytes:
        """Associated data binding a stored share to its exact slot.

        Stops a share being moved to a different block or variant and still
        decrypting.
        """
        return f"{doc_id}:{block_idx}:{variant}".encode("utf-8")

    def wrap_share(self, share_bytes: bytes, context: bytes) -> bytes:
        """Encrypt one share for storage: ``nonce || AES-GCM(share)``."""
        nonce = os.urandom(12)
        return nonce + AESGCM(self._share_wrap_key).encrypt(nonce, share_bytes, context)

    def unwrap_share(self, wrapped: bytes, context: bytes) -> bytes:
        """Decrypt a stored share."""
        if len(wrapped) < 12 + 16:
            raise ValueError("Stored share is too short to be wrapped ciphertext")
        nonce, sealed = wrapped[:12], wrapped[12:]
        return AESGCM(self._share_wrap_key).decrypt(nonce, sealed, context)

    def store_shares(self, doc_id: str, shares_records: List[Dict[str, Any]]) -> int:
        """Wrap each incoming share and store it encrypted.

        Args:
            doc_id: Document the shares belong to.
            shares_records: Each needs ``block_idx``, ``variant``,
                ``share_index`` and ``encrypted_share`` (base64 or raw).

        Returns:
            Number of shares stored.
        """
        prepared = []
        for share in shares_records:
            raw = share["encrypted_share"]
            share_bytes = b64_decode(raw) if isinstance(raw, str) else raw
            prepared.append(
                {
                    "block_idx": share["block_idx"],
                    "variant": share["variant"],
                    "share_index": share["share_index"],
                    "encrypted_share": self.wrap_share(
                        share_bytes,
                        self.share_context(doc_id, share["block_idx"], share["variant"]),
                    ),
                }
            )
        self.ledger.store_key_shares(doc_id, prepared)
        return len(prepared)

    def read_share(self, doc_id: str, block_idx: int, variant: int, share_index: int) -> bytes:
        """Fetch one stored share and unwrap it."""
        stored = self.ledger.get_key_share(doc_id, block_idx, variant, share_index=share_index)
        if not stored:
            raise RuntimeError(
                f"Missing key share for doc {doc_id} block {block_idx} variant {variant}"
            )
        return self.unwrap_share(stored, self.share_context(doc_id, block_idx, variant))

    def release_shares_for_committed_session(
        self,
        doc_id: str,
        session_entry_hash_hex: str,
        ephemeral_ml_kem_pk_bytes: bytes,
        total_blocks: int,
    ) -> Dict[str, Any]:
        """Release the codeword-selected shares for a committed session.

        Args:
            doc_id: Document identifier.
            session_entry_hash_hex: Hex hash of the committed DECRYPT_REQUEST.
            ephemeral_ml_kem_pk_bytes: Recipient's single-use ML-KEM key.
            total_blocks: Number of blocks M.

        Returns:
            The NODE_KEY_RELEASE wire payload.

        Raises:
            PermissionError: if the session is not committed on the ledger.
        """
        # 1. The session must be committed. This is the "no log, no key" gate.
        entry_record = self.ledger.get_entry(session_entry_hash_hex)
        if not entry_record:
            raise PermissionError(
                f"Entry {session_entry_hash_hex} is not committed on the ledger"
            )
        if entry_record["entry_type"] != "DECRYPT_REQUEST":
            raise ValueError(f"Entry {session_entry_hash_hex} is not a DECRYPT_REQUEST")

        # 2. Derive the session codeword: c = PRF(K_wm, session_entry_hash)
        session_hash_bytes = bytes.fromhex(session_entry_hash_hex)
        codeword = generate_codeword_bits(self.wm_master_seed, session_hash_bytes, total_blocks)

        # 3. Collect and unwrap this node's share for each selected variant
        released_shares = []
        for block_idx in range(total_blocks):
            chosen_variant = codeword[block_idx]
            raw_share = self.read_share(doc_id, block_idx, chosen_variant, self.share_index)
            released_shares.append(
                {
                    "block_idx": block_idx,
                    "variant": chosen_variant,
                    "share_index": self.share_index,
                    "share_data_b64": b64_encode(raw_share),
                }
            )

        # 4. Encapsulate to the recipient's ephemeral ML-KEM key
        shared_secret, kem_ciphertext = MLKEM768.encaps(ephemeral_ml_kem_pk_bytes)

        # 5. Seal the released bundle to that shared secret
        bundle_bytes = json.dumps(released_shares).encode("utf-8")
        nonce = os.urandom(12)
        encrypted_bundle = AESGCM(shared_secret).encrypt(
            nonce, bundle_bytes, associated_data=session_hash_bytes
        )

        return {
            "validator_id": self.node_id,
            "share_index": self.share_index,
            "doc_id": doc_id,
            "session_entry_hash": session_entry_hash_hex,
            "block_height": entry_record["block_height"],
            "ephemeral_capsule": b64_encode(kem_ciphertext),
            "nonce": b64_encode(nonce),
            "encrypted_shares_bundle": b64_encode(encrypted_bundle),
        }


__all__ = [
    "KeyCustodyManager",
    "SHARE_KEY_FILENAME",
    "load_or_create_share_key",
]

