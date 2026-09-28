"""End-to-End Walking Skeleton Integration Test for CANARY TRAP.

Validates the complete "No log, no key" lifecycle in code:
1. Enrolls two recipients (Alice and Bob) with real ML-KEM-768 and ML-DSA-65 keys.
2. Sender splits a sample PDF, encrypts A/B variants, Shamir-splits keys, and commits manifest.
3. Alice requests decryption:
   - Alice signs DECRYPT_REQUEST with ML-DSA-65.
   - Validator commits request into a block.
   - Validator releases encrypted variant key shares.
   - Alice reconstructs keys, decrypts variants, and assembles PDF.
4. Bob requests decryption for the same file:
   - Both documents are visually identical.
   - Both documents have distinct forensic codewords matching their respective sessions.
5. Verifies "No Log, No Key" enforcement:
   - Client cannot obtain keys or assemble PDF without committed block.
"""

import os
import shutil
import fitz
import pytest

from seal.pqc_adapter import MLKEM768, MLDSA65, b64_decode, b64_encode
from chronicle.ledger import Ledger
from warden.policy import PolicyEngine
from warden.custody import KeyCustodyManager
from seal.container import ContainerBuilder
from bridge.session import RecipientCryptoSession
from dye.extractor import WatermarkExtractor
from dye.codeword import generate_codeword_bits


@pytest.fixture
def clean_env(tmp_path):
    """Set up temporary directory for ledger, client keys, and test files."""
    test_dir = str(tmp_path / "ct_test_env")
    os.makedirs(test_dir, exist_ok=True)
    db_path = os.path.join(test_dir, "test_ledger.db")
    keys_dir = os.path.join(test_dir, "client_keys")

    # Master watermark seed
    wm_seed = b"TEST_MASTER_WATERMARK_SEED_2026"

    # Validator keypair
    val_vk, val_sk = MLDSA65.keygen()

    ledger = Ledger(db_path=db_path, node_id="TEST_NODE_01")
    policy = PolicyEngine(ledger=ledger)
    # Custody Managers for 3 nodes (threshold t=3)
    custody1 = KeyCustodyManager(ledger=ledger, node_id="TEST_NODE_01", node_share_index=1, wm_master_seed=wm_seed)
    custody2 = KeyCustodyManager(ledger=ledger, node_id="TEST_NODE_02", node_share_index=2, wm_master_seed=wm_seed)
    custody3 = KeyCustodyManager(ledger=ledger, node_id="TEST_NODE_03", node_share_index=3, wm_master_seed=wm_seed)

    # Sender keypair
    sender_vk, sender_sk = MLDSA65.keygen()

    # Generate a sample 2-page, 6-block PDF
    sample_pdf = os.path.join(test_dir, "source_document.pdf")
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    lines = [
        "CONFIDENTIAL POLICY DIRECTIVE 2026 - NATIONAL ARCHIVES",
        "Section 1: Post-Quantum Security Requirements for Inter-Agency Distribution",
        "Section 2: Decentralized Ledger Commits for Zero-Trust Non-Repudiation",
        "Section 3: Invisible Forensic Watermarking for Forensic Leak Attribution",
        "Section 4: Air-Gapped Threshold Key Custody Across Administrative Quorums",
        "Section 5: Mathematical Verification of Electronic Provenance Records"
    ]
    y = 100
    for l in lines:
        page.insert_text((72, y), l, fontsize=12)
        y += 60
    doc.save(sample_pdf)
    doc.close()

    yield {
        "test_dir": test_dir,
        "sample_pdf": sample_pdf,
        "keys_dir": keys_dir,
        "ledger": ledger,
        "policy": policy,
        "custody_nodes": [custody1, custody2, custody3],
        "val_sk": val_sk,
        "val_vk": val_vk,
        "sender_sk": sender_sk,
        "sender_vk": sender_vk,
        "wm_seed": wm_seed
    }


def test_walking_skeleton_end_to_end(clean_env):
    env = clean_env
    ledger = env["ledger"]
    policy = env["policy"]
    custody_nodes = env["custody_nodes"]
    val_sk = env["val_sk"]

    # ========================================================================
    # 1. Identity Enrollment (Alice & Bob)
    # ========================================================================
    alice = RecipientCryptoSession(recipient_id="ALICE", keys_dir=env["keys_dir"])
    bob = RecipientCryptoSession(recipient_id="BOB", keys_dir=env["keys_dir"])

    for recipient in [alice, bob]:
        payload, sig_b64 = recipient.get_enroll_payload()
        is_val, reason = policy.validate_enroll_request(payload, b64_decode(sig_b64))
        assert is_val is True, reason

        # Commit ENROLL block
        entry = {
            "entry_type": "ENROLL",
            "payload": payload,
            "signature": b64_decode(sig_b64),
            "signer_id": recipient.recipient_id
        }
        res = ledger.commit_block([entry], proposer_id="TEST_NODE_01", validator_sigs={"TEST_NODE_01": b"dummy_sig"})
        assert res["height"] > 0

    # ========================================================================
    # 2. Document Distribution (Sender packages .ct container)
    # ========================================================================
    recipients_map = {
        "ALICE": alice.kem_pk,
        "BOB": bob.kem_pk
    }
    doc_id = "DOC_POLICY_2026"

    container_bytes, signed_manifest, node_shares = ContainerBuilder.build_container(
        pdf_path=env["sample_pdf"],
        doc_id=doc_id,
        recipients_map=recipients_map,
        sender_sk=env["sender_sk"],
        lines_per_block=1  # 6 blocks total
    )

    # Commit MANIFEST
    man_entry = {
        "entry_type": "MANIFEST",
        "payload": signed_manifest["payload"],
        "signature": b64_decode(signed_manifest["signature_b64"]),
        "signer_id": "SENDER_OFFICE"
    }
    man_res = ledger.commit_block([man_entry], proposer_id="TEST_NODE_01", validator_sigs={"TEST_NODE_01": b"dummy_sig"})
    assert man_res["height"] > 0

    # Deposit Key Shares for Nodes 1, 2, and 3
    for node_idx in [1, 2, 3]:
        ledger.store_key_shares(doc_id, node_shares[node_idx])

    # ========================================================================
    # 3. Alice Decryption Session ("Log Before Key")
    # ========================================================================
    # Alice unwraps outer container
    d_id, alice_meta, alice_enc_blocks = alice.unwrap_container(container_bytes)
    assert d_id == doc_id
    assert len(alice_enc_blocks) == 6

    # Alice creates and signs DECRYPT_REQUEST
    alice_req, alice_sig, alice_eph_dk = alice.create_decrypt_request(doc_id)
    is_val, reason, _ = policy.validate_decrypt_request(alice_req, b64_decode(alice_sig))
    assert is_val is True, reason

    # Validator commits request into a block
    req_entry_alice = {
        "entry_type": "DECRYPT_REQUEST",
        "payload": alice_req,
        "signature": b64_decode(alice_sig),
        "signer_id": "ALICE"
    }
    alice_commit = ledger.commit_block([req_entry_alice], proposer_id="TEST_NODE_01", validator_sigs={"TEST_NODE_01": b"dummy_sig"})
    alice_session_hash = alice_commit["entry_hashes"][0]

    # Quorum nodes 1, 2, and 3 release key shares for Alice
    alice_releases = [
        c_node.release_shares_for_committed_session(
            doc_id=doc_id,
            session_entry_hash_hex=alice_session_hash,
            ephemeral_ml_kem_pk_bytes=b64_decode(alice_req["ephemeral_ml_kem_pk"]),
            total_blocks=6
        )
        for c_node in custody_nodes
    ]

    # Alice reconstructs keys, decrypts blocks, and produces PDF
    alice_pdf_bytes = alice.reconstruct_and_assemble(
        doc_id=doc_id,
        doc_meta=alice_meta,
        encrypted_blocks=alice_enc_blocks,
        release_bundles=alice_releases,
        ephemeral_dk_bytes=alice_eph_dk
    )
    assert len(alice_pdf_bytes) > 0

    # ========================================================================
    # 4. Bob Decryption Session
    # ========================================================================
    _, bob_meta, bob_enc_blocks = bob.unwrap_container(container_bytes)
    bob_req, bob_sig, bob_eph_dk = bob.create_decrypt_request(doc_id)

    req_entry_bob = {
        "entry_type": "DECRYPT_REQUEST",
        "payload": bob_req,
        "signature": b64_decode(bob_sig),
        "signer_id": "BOB"
    }
    bob_commit = ledger.commit_block([req_entry_bob], proposer_id="TEST_NODE_01", validator_sigs={"TEST_NODE_01": b"dummy_sig"})
    bob_session_hash = bob_commit["entry_hashes"][0]

    bob_releases = [
        c_node.release_shares_for_committed_session(
            doc_id=doc_id,
            session_entry_hash_hex=bob_session_hash,
            ephemeral_ml_kem_pk_bytes=b64_decode(bob_req["ephemeral_ml_kem_pk"]),
            total_blocks=6
        )
        for c_node in custody_nodes
    ]

    bob_pdf_bytes = bob.reconstruct_and_assemble(
        doc_id=doc_id,
        doc_meta=bob_meta,
        encrypted_blocks=bob_enc_blocks,
        release_bundles=bob_releases,
        ephemeral_dk_bytes=bob_eph_dk
    )
    assert len(bob_pdf_bytes) > 0

    # ========================================================================
    # 5. Verify Forensic Attribution & Watermark Provenance
    # ========================================================================
    # Compute expected codewords for both sessions
    expected_alice_cw = generate_codeword_bits(env["wm_seed"], bytes.fromhex(alice_session_hash), 6)
    expected_bob_cw = generate_codeword_bits(env["wm_seed"], bytes.fromhex(bob_session_hash), 6)

    # Extract codeword from Alice's decrypted PDF
    recovered_alice_cw, _ = WatermarkExtractor.extract_from_pdf(alice_pdf_bytes, total_expected_blocks=6, lines_per_block=1)
    # Extract codeword from Bob's decrypted PDF
    recovered_bob_cw, _ = WatermarkExtractor.extract_from_pdf(bob_pdf_bytes, total_expected_blocks=6, lines_per_block=1)

    assert recovered_alice_cw == expected_alice_cw, f"Alice recovery failed: {recovered_alice_cw} != {expected_alice_cw}"
    assert recovered_bob_cw == expected_bob_cw, f"Bob recovery failed: {recovered_bob_cw} != {expected_bob_cw}"

    # Verify both PDFs contain identical text
    doc_a = fitz.open(stream=alice_pdf_bytes, filetype="pdf")
    doc_b = fitz.open(stream=bob_pdf_bytes, filetype="pdf")
    text_a = doc_a[0].get_text()
    text_b = doc_b[0].get_text()
    assert text_a.strip() == text_b.strip(), "Both decrypted documents must have 100% identical text!"

    # But their binary content and hashes differ because of forensic fingerprinting!
    assert alice_pdf_bytes != bob_pdf_bytes, "Decrypted copies must be forensically distinct!"

    # ========================================================================
    # 6. Verify "No Log, No Key" Enforcement
    # ========================================================================
    # A malicious client attempts to call release_shares without committing request
    fake_entry_hash = "f" * 64
    with pytest.raises(PermissionError):
        custody_nodes[0].release_shares_for_committed_session(
            doc_id=doc_id,
            session_entry_hash_hex=fake_entry_hash,
            ephemeral_ml_kem_pk_bytes=alice.kem_pk,
            total_blocks=6
        )

    # Verify chain integrity
    is_intact, err = ledger.verify_integrity()
    assert is_intact is True, err
