"""Policy enforcement and authorization for validator nodes.

Checks applied to each request type:
- ``ENROLL`` — well-formed public keys, and a valid self-signature.
- ``MANIFEST`` — the sender's ML-DSA-65 signature over the manifest, verified
  against the registered sender key. Previously this was stored but never
  checked, which let anyone who could reach the endpoint register a manifest
  naming arbitrary recipients.
- ``DECRYPT_REQUEST`` — recipient enrolled and not revoked, valid recipient
  signature, manifest exists, not expired, recipient authorised, quota remaining.
"""

import json
import time
from typing import Any, Dict, Optional, Tuple

from seal.pqc_adapter import MLDSA65, b64_decode
from chronicle.ledger import Ledger


class PolicyEngine:
    """Zero-trust access control and cryptographic authentication."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    def validate_enroll_request(self, payload: Dict[str, Any], signature: bytes) -> Tuple[bool, str]:
        """Validate an identity enrollment request."""
        recipient_id = payload.get("recipient_id")
        ml_dsa_pk_b64 = payload.get("ml_dsa_public_key")
        ml_kem_pk_b64 = payload.get("ml_kem_public_key")

        if not recipient_id or not ml_dsa_pk_b64 or not ml_kem_pk_b64:
            return False, "Missing required enrollment fields"

        try:
            dsa_pk = b64_decode(ml_dsa_pk_b64)
            kem_pk = b64_decode(ml_kem_pk_b64)
        except Exception:
            return False, "Invalid Base64 public keys"

        if len(dsa_pk) != MLDSA65.PUBLIC_KEY_SIZE:
            return False, f"Invalid ML-DSA-65 public key size ({len(dsa_pk)})"
        if len(kem_pk) != 1184:
            return False, f"Invalid ML-KEM-768 public key size ({len(kem_pk)})"

        if not MLDSA65.verify(dsa_pk, payload, signature):
            return False, "Enrollment self-signature verification failed"

        return True, "Valid enrollment request"

    def validate_manifest_request(
        self, payload: Dict[str, Any], signature: bytes
    ) -> Tuple[bool, str]:
        """Validate a document manifest submitted by a sender.

        The manifest is what fixes the authorised recipient list, so an unsigned
        or wrongly signed manifest is a privilege-escalation path. This verifies
        the sender's signature against the sender's registered public key.

        Senders register through ``ENROLL`` with an ``authority`` field, so a
        sender key and a recipient key are looked up the same way.
        """
        doc_id = payload.get("doc_id")
        sender_id = payload.get("sender_id")
        container_hash = payload.get("container_hash")
        authorized = payload.get("authorized_recipients")
        total_blocks = payload.get("total_blocks")
        expiry = payload.get("expiry")
        quota = payload.get("quota_per_recipient")

        if not doc_id:
            return False, "Manifest is missing doc_id"
        if not sender_id:
            return False, "Manifest is missing sender_id"
        if not container_hash:
            return False, "Manifest is missing container_hash"
        if not isinstance(authorized, list) or not authorized:
            return False, "Manifest must list at least one authorized recipient"
        if not isinstance(total_blocks, int) or total_blocks <= 0:
            return False, "Manifest must declare a positive total_blocks"
        if not isinstance(expiry, int) or expiry <= 0:
            return False, "Manifest must declare a positive expiry"
        if not isinstance(quota, int) or quota <= 0:
            return False, "Manifest must declare a positive quota_per_recipient"

        try:
            container_bytes = bytes.fromhex(container_hash)
        except Exception:
            return False, "container_hash is not valid hex"
        if len(container_bytes) != 32:
            return False, f"container_hash must be 32 bytes, got {len(container_bytes)}"

        if expiry < int(time.time()):
            return False, f"Manifest for '{doc_id}' has already expired"

        # The sender must be a known, enrolled identity.
        with self.ledger._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ml_dsa_public_key, is_revoked FROM enrolled_identities "
                "WHERE recipient_id = ?;",
                (sender_id,),
            )
            sender = cursor.fetchone()

        if not sender:
            return False, f"Sender '{sender_id}' is not enrolled on the ledger"
        if sender["is_revoked"]:
            return False, f"Sender '{sender_id}' enrollment is revoked"

        # Every authorised recipient must be enrolled too, otherwise the manifest
        # authorises a key nobody can attribute a decryption session to.
        with self.ledger._get_conn() as conn:
            cursor = conn.cursor()
            for recipient_id in authorized:
                cursor.execute(
                    "SELECT 1 FROM enrolled_identities WHERE recipient_id = ?;",
                    (recipient_id,),
                )
                if cursor.fetchone() is None:
                    return False, f"Authorized recipient '{recipient_id}' is not enrolled"

        if not MLDSA65.verify(sender["ml_dsa_public_key"], payload, signature):
            return False, f"Sender ML-DSA-65 signature verification failed for '{sender_id}'"

        return True, "Valid manifest"


    def validate_decrypt_request(self, payload: Dict[str, Any], signature: bytes) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Validate a decryption request against policy and on-ledger state.
        
        Returns:
            (is_valid, reason_str, recipient_identity_record)
        """
        doc_id = payload.get("doc_id")
        recipient_id = payload.get("recipient_id")
        ephemeral_pk_b64 = payload.get("ephemeral_ml_kem_pk")
        nonce = payload.get("session_nonce")

        if not doc_id or not recipient_id or not ephemeral_pk_b64 or not nonce:
            return False, "Missing required decryption request fields", None

        # 1. Check Recipient Enrollment
        with self.ledger._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM enrolled_identities WHERE recipient_id = ?;", (recipient_id,))
            identity = cur.fetchone()

        if not identity:
            return False, f"Recipient '{recipient_id}' is not enrolled on the ledger", None
        if identity["is_revoked"]:
            return False, f"Recipient '{recipient_id}' enrollment is revoked", None

        # 2. Verify Recipient ML-DSA Signature
        recipient_dsa_pk = identity["ml_dsa_public_key"]
        if not MLDSA65.verify(recipient_dsa_pk, payload, signature):
            return False, "Recipient ML-DSA-65 signature verification failed", None

        # 3. Check Document Manifest & Authorization
        with self.ledger._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM manifests WHERE doc_id = ?;", (doc_id,))
            manifest = cur.fetchone()

        if not manifest:
            return False, f"Document manifest for '{doc_id}' not found on ledger", None

        now = int(time.time())
        if manifest["expiry"] < now:
            return False, f"Document '{doc_id}' access has expired", None

        authorized_list = json.loads(manifest["authorized_recipients"])
        if recipient_id not in authorized_list:
            return False, f"Recipient '{recipient_id}' is not authorized for document '{doc_id}'", None

        # 4. Check Decryption Quota
        quota = manifest["quota"]
        with self.ledger._get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM entries "
                "WHERE entry_type = 'DECRYPT_REQUEST' AND signer_id = ? AND payload LIKE ?;",
                (recipient_id, f'%"{doc_id}"%')
            )
            count = cur.fetchone()[0]

        if count >= quota:
            return False, f"Recipient '{recipient_id}' has exceeded decryption quota ({count}/{quota})", None

        return True, "Authorized and validated", dict(identity)
