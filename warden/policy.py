"""Policy Enforcement and Authorization Logic for CANARY TRAP Validator Nodes.

Checks:
- Recipient identity enrollment and revocation status
- Document manifest existence and recipient authorization
- Document expiry and decryption quotas
- Cryptographic verification of recipient ML-DSA-65 signatures
"""

import json
import time
from typing import Tuple, Dict, Any, Optional

from seal.pqc_adapter import MLDSA65, b64_decode
from chronicle.ledger import Ledger


class PolicyEngine:
    """Enforces zero-trust access control and cryptographic authentication."""

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

        # Verify self-signature
        if not MLDSA65.verify(dsa_pk, payload, signature):
            return False, "Enrollment self-signature verification failed"

        return True, "Valid enrollment request"

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
