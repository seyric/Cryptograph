"""Recipient Client Cryptographic Daemon Subsystem for CANARY TRAP.

Handles on-device cryptographic duties:
- Recipient ML-KEM-768 and ML-DSA-65 private keys (never leave local device)
- Container outer lock decapsulation (unwraps K_out)
- Canonical DECRYPT_REQUEST construction and ML-DSA-65 signing
- Shamir share Lagrange interpolation over F_p to reconstruct variant keys
- Variant block AES-256-GCM decryption and in-memory watermarked PDF assembly
"""

import os
import json
import time
from typing import Dict, Any, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from seal.pqc_adapter import MLKEM768, MLDSA65, b64_encode, b64_decode
from seal.sharing import ShamirSecretSharing
from dye.assembler import VariantGenerator
from dye.text_layer import TextBlock


class RecipientCryptoSession:
    """Manages local private keys, request signing, and key reconstruction."""

    def __init__(self, recipient_id: str, keys_dir: str = "data/client_keys"):
        self.recipient_id = recipient_id
        self.keys_dir = keys_dir
        os.makedirs(keys_dir, exist_ok=True)

        self.kem_pk_path = os.path.join(keys_dir, f"{recipient_id}_kem_pk.bin")
        self.kem_sk_path = os.path.join(keys_dir, f"{recipient_id}_kem_sk.bin")
        self.dsa_pk_path = os.path.join(keys_dir, f"{recipient_id}_dsa_pk.bin")
        self.dsa_sk_path = os.path.join(keys_dir, f"{recipient_id}_dsa_sk.bin")

        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        if os.path.exists(self.kem_pk_path) and os.path.exists(self.dsa_sk_path):
            with open(self.kem_pk_path, "rb") as f: self.kem_pk = f.read()
            with open(self.kem_sk_path, "rb") as f: self.kem_sk = f.read()
            with open(self.dsa_pk_path, "rb") as f: self.dsa_pk = f.read()
            with open(self.dsa_sk_path, "rb") as f: self.dsa_sk = f.read()
        else:
            self.kem_pk, self.kem_sk = MLKEM768.keygen()
            self.dsa_pk, self.dsa_sk = MLDSA65.keygen()
            with open(self.kem_pk_path, "wb") as f: f.write(self.kem_pk)
            with open(self.kem_sk_path, "wb") as f: f.write(self.kem_sk)
            with open(self.dsa_pk_path, "wb") as f: f.write(self.dsa_pk)
            with open(self.dsa_sk_path, "wb") as f: f.write(self.dsa_sk)

    def get_enroll_payload(self) -> Tuple[Dict[str, Any], str]:
        """Prepare identity enrollment payload and self-signature."""
        payload = {
            "type": "ENROLL",
            "recipient_id": self.recipient_id,
            "ml_kem_public_key": b64_encode(self.kem_pk),
            "ml_dsa_public_key": b64_encode(self.dsa_pk),
            "timestamp": int(time.time()),
            "device_fingerprint": "DEV_CT_HOST_01"
        }
        sig = MLDSA65.sign(self.dsa_sk, payload)
        return payload, b64_encode(sig)

    def unwrap_container(self, container_bytes: bytes) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
        """Unwrap outer container key K_out and unpack encrypted blocks.
        
        Returns:
            (doc_id, doc_meta, encrypted_blocks)
        """
        container_dict = json.loads(container_bytes.decode("utf-8"))
        doc_id = container_dict["doc_id"]
        capsules = container_dict["recipient_capsules"]

        # Find my capsule
        my_capsule = None
        for cap in capsules:
            if cap["recipient_id"] == self.recipient_id:
                my_capsule = cap
                break

        if not my_capsule:
            raise PermissionError(f"Recipient '{self.recipient_id}' not authorized in this container")

        # Decapsulate ML-KEM shared secret
        kem_ct = b64_decode(my_capsule["kem_ciphertext"])
        ss = MLKEM768.decaps(self.kem_sk, kem_ct)

        # Decrypt K_out
        nonce = b64_decode(my_capsule["nonce"])
        wrapped_kout = b64_decode(my_capsule["wrapped_k_out"])
        aes_outer = AESGCM(ss)
        k_out = aes_outer.decrypt(nonce, wrapped_kout, associated_data=self.recipient_id.encode("utf-8"))

        # Decrypt Inner Content Package
        nonce_inner = b64_decode(container_dict["nonce"])
        encrypted_inner = b64_decode(container_dict["encrypted_inner_bytes"])
        aes_inner = AESGCM(k_out)
        inner_bytes = aes_inner.decrypt(nonce_inner, encrypted_inner, associated_data=doc_id.encode("utf-8"))
        inner_content = json.loads(inner_bytes.decode("utf-8"))

        return doc_id, inner_content["doc_meta"], inner_content["blocks"]

    def create_decrypt_request(self, doc_id: str) -> Tuple[Dict[str, Any], str, bytes]:
        """Create a signed DECRYPT_REQUEST payload and ephemeral ML-KEM secret key.
        
        Returns:
            (payload_dict, signature_b64, ephemeral_dk_bytes)
        """
        # Generate single-use ephemeral keypair
        eph_ek, eph_dk = MLKEM768.keygen()

        nonce = os.urandom(16).hex()
        now = int(time.time())

        payload = {
            "type": "DECRYPT_REQUEST",
            "doc_id": doc_id,
            "recipient_id": self.recipient_id,
            "session_nonce": nonce,
            "ephemeral_ml_kem_pk": b64_encode(eph_ek),
            "timestamp": now
        }

        sig = MLDSA65.sign(self.dsa_sk, payload)
        return payload, b64_encode(sig), eph_dk

    def reconstruct_and_assemble(
        self,
        doc_id: str,
        doc_meta: Dict[str, Any],
        encrypted_blocks: List[Dict[str, Any]],
        release_bundles: List[Dict[str, Any]],
        ephemeral_dk_bytes: bytes
    ) -> bytes:
        """Reconstruct variant AES keys from Shamir shares, decrypt blocks, and assemble PDF.
        
        Args:
            doc_id: Document ID.
            doc_meta: Document layout metadata.
            encrypted_blocks: Encrypted block payloads from container.
            release_bundles: List of key release responses from >= 1 validator nodes.
            ephemeral_dk_bytes: Ephemeral ML-KEM secret key used for this session.
            
        Returns:
            Decrypted, watermarked PDF bytes.
        """
        # 1. Decrypt shares from each release bundle
        shares_by_block: Dict[int, Dict[int, List[Tuple[int, bytes]]]] = {}
        # shares_by_block[block_idx][variant] = [(share_idx, y_bytes), ...]

        for bundle in release_bundles:
            # Decapsulate ephemeral ML-KEM key
            kem_ct = b64_decode(bundle["ephemeral_capsule"])
            ss = MLKEM768.decaps(ephemeral_dk_bytes, kem_ct)

            # Decrypt shares bundle
            nonce = b64_decode(bundle["nonce"])
            ct = b64_decode(bundle["encrypted_shares_bundle"])
            session_hash_bytes = bytes.fromhex(bundle["session_entry_hash"])

            aes = AESGCM(ss)
            bundle_bytes = aes.decrypt(nonce, ct, associated_data=session_hash_bytes)
            shares_list = json.loads(bundle_bytes.decode("utf-8"))

            for s in shares_list:
                b_idx = s["block_idx"]
                var_choice = s["variant"]
                sh_idx = s["share_index"]
                raw_y = b64_decode(s["share_data_b64"])

                shares_by_block.setdefault(b_idx, {}).setdefault(var_choice, []).append((sh_idx, raw_y))

        # 2. Reconstruct variant AES keys via Lagrange interpolation and decrypt each block
        assembled_blocks: List[TextBlock] = []
        recovered_codeword = []

        for b_dict in encrypted_blocks:
            j = b_dict["block_idx"]
            page_idx = b_dict["page_idx"]

            if j not in shares_by_block:
                raise RuntimeError(f"Missing key shares for block {j}")

            # For each block, quorum returned shares for ONE variant choice
            chosen_variant = list(shares_by_block[j].keys())[0]
            shares = shares_by_block[j][chosen_variant]

            if len(shares) < 3:
                raise ValueError(f"Insufficient Shamir shares for block {j}: need >= 3, got {len(shares)}")

            k_variant = ShamirSecretSharing.reconstruct(shares[:3])

            # Decrypt chosen variant stream
            ct_full = b64_decode(b_dict["v1" if chosen_variant == 1 else "v0"])
            nonce_blk = ct_full[:12]
            ct_blk = ct_full[12:]

            aad = f"{doc_id}:{j}:{chosen_variant}".encode("utf-8")
            aes_blk = AESGCM(k_variant)
            stream_bytes = aes_blk.decrypt(nonce_blk, ct_blk, associated_data=aad)

            tb = TextBlock(block_idx=j, page_idx=page_idx)
            if chosen_variant == 1:
                tb.variant_1_stream = stream_bytes
            else:
                tb.variant_0_stream = stream_bytes

            assembled_blocks.append(tb)
            recovered_codeword.append(chosen_variant)

        # 3. Stitch blocks into PDF
        pdf_bytes = VariantGenerator.assemble_pdf(assembled_blocks, doc_meta, recovered_codeword)
        return pdf_bytes
