"""Container Builder for CANARY TRAP Document Senders.

Transforms a source PDF into a secure .ct container:
- Splits PDF into TextBlocks
- Renders A/B variant streams
- Encrypts each variant with an independent single-use AES-256-GCM key
- Shamir-splits variant keys (t=3, n=4) for quorum custody
- Wraps outer content key K_out to each authorized recipient using ML-KEM-768
- Exports manifest and container file
"""

import os
import json
import struct
import hashlib
import time
from typing import List, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from seal.pqc_adapter import MLKEM768, MLDSA65, b64_encode, canonical_json
from seal.sharing import ShamirSecretSharing
from dye.text_layer import PDFSegmenter


CT_MAGIC = b"CANARY TRAP\x01"


class ContainerBuilder:
    """Builds two-lock broadcast containers (.ct) and partitions variant keys."""

    @classmethod
    def build_container(
        cls,
        pdf_path: str,
        doc_id: str,
        recipients_map: Dict[str, bytes],  # recipient_id -> ML-KEM public key (1184 bytes)
        sender_sk: bytes,                  # Sender ML-DSA-65 private key
        sender_id: str = "SENDER_OFFICE",
        lines_per_block: int = 3,
        expiry_seconds: int = 86400 * 7,   # 7 days
        quota_per_recipient: int = 5
    ) -> Tuple[bytes, Dict[str, Any], Dict[int, List[Dict[str, Any]]]]:
        """Build a .ct container and prepare Shamir shares for validator custody.
        
        Args:
            pdf_path: Path to source PDF.
            doc_id: Unique document identifier.
            recipients_map: Dict of recipient_id -> enrolled ML-KEM-768 public key bytes.
            sender_sk: Sender ML-DSA-65 signing key.
            sender_id: Sender organization or office ID.
            lines_per_block: Lines grouped per variation block.
            expiry_seconds: Expiry relative to current timestamp.
            quota_per_recipient: Maximum decryptions permitted per recipient.
            
        Returns:
            (container_bytes, signed_manifest_dict, node_shares_by_share_index)
        """
        # 1. Segment PDF
        blocks, doc_meta = PDFSegmenter.segment_pdf(pdf_path, lines_per_block=lines_per_block)
        total_blocks = len(blocks)
        if total_blocks == 0:
            raise ValueError("Document contains no text blocks to segment")

        # 2. Encrypt Variants & Shamir-Split Keys
        node_shares: Dict[int, List[Dict[str, Any]]] = {1: [], 2: [], 3: [], 4: []}
        encrypted_blocks = []

        for b in blocks:
            j = b.block_idx

            # Generate independent single-use keys
            k_v0 = os.urandom(32)
            k_v1 = os.urandom(32)

            # Encrypt Variant 0
            nonce_0 = os.urandom(12)
            aad_0 = f"{doc_id}:{j}:0".encode("utf-8")
            aes_0 = AESGCM(k_v0)
            ct_0 = aes_0.encrypt(nonce_0, b.variant_0_stream, associated_data=aad_0)

            # Encrypt Variant 1
            nonce_1 = os.urandom(12)
            aad_1 = f"{doc_id}:{j}:1".encode("utf-8")
            aes_1 = AESGCM(k_v1)
            ct_1 = aes_1.encrypt(nonce_1, b.variant_1_stream, associated_data=aad_1)

            encrypted_blocks.append({
                "block_idx": j,
                "page_idx": b.page_idx,
                "v0": b64_encode(nonce_0 + ct_0),
                "v1": b64_encode(nonce_1 + ct_1)
            })

            # Shamir-split both keys (t=3, n=4)
            shares_v0 = ShamirSecretSharing.split(k_v0, t=3, n=4)
            shares_v1 = ShamirSecretSharing.split(k_v1, t=3, n=4)

            # Deposit shares for each node (1..4)
            for x, y_bytes in shares_v0:
                node_shares[x].append({
                    "block_idx": j,
                    "variant": 0,
                    "share_index": x,
                    "encrypted_share": b64_encode(y_bytes)
                })
            for x, y_bytes in shares_v1:
                node_shares[x].append({
                    "block_idx": j,
                    "variant": 1,
                    "share_index": x,
                    "encrypted_share": b64_encode(y_bytes)
                })

            # Memory wipe of plaintext keys
            del k_v0
            del k_v1

        # 3. Outer Broadcast Encryption with K_out
        k_out = os.urandom(32)
        recipient_capsules = []

        for r_id, r_kem_pk in recipients_map.items():
            # Encapsulate to recipient's ML-KEM-768 public key
            ss, kem_ct = MLKEM768.encaps(r_kem_pk)
            aes_outer = AESGCM(ss)
            nonce_kout = os.urandom(12)
            wrapped_kout = aes_outer.encrypt(nonce_kout, k_out, associated_data=r_id.encode("utf-8"))
            recipient_capsules.append({
                "recipient_id": r_id,
                "kem_ciphertext": b64_encode(kem_ct),
                "nonce": b64_encode(nonce_kout),
                "wrapped_k_out": b64_encode(wrapped_kout)
            })

        # 4. Encrypt Inner Content Package Under K_out
        inner_content = {
            "doc_id": doc_id,
            "doc_meta": doc_meta,
            "blocks": encrypted_blocks
        }
        inner_bytes = json.dumps(inner_content).encode("utf-8")
        nonce_inner = os.urandom(12)
        aes_container = AESGCM(k_out)
        encrypted_inner = aes_container.encrypt(nonce_inner, inner_bytes, associated_data=doc_id.encode("utf-8"))

        del k_out

        # 5. Assemble Container Binary
        container_payload = {
            "magic": "canarytrap/v1",
            "doc_id": doc_id,
            "recipient_capsules": recipient_capsules,
            "nonce": b64_encode(nonce_inner),
            "encrypted_inner_bytes": b64_encode(encrypted_inner)
        }
        container_bytes = json.dumps(container_payload).encode("utf-8")
        container_hash = hashlib.sha3_256(container_bytes).hexdigest()

        # 6. Build and Sign MANIFEST
        now = int(time.time())
        manifest_payload = {
            "type": "MANIFEST",
            "doc_id": doc_id,
            "container_hash": container_hash,
            "authorized_recipients": list(recipients_map.keys()),
            "total_blocks": total_blocks,
            "expiry": now + expiry_seconds,
            "quota_per_recipient": quota_per_recipient,
            "sender_id": sender_id,
            "timestamp": now
        }
        manifest_sig = MLDSA65.sign(sender_sk, manifest_payload)

        signed_manifest = {
            "payload": manifest_payload,
            "signature_b64": b64_encode(manifest_sig)
        }

        return container_bytes, signed_manifest, node_shares
