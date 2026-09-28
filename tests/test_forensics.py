"""Unit Tests for Forensic Lab Accusation and Offline Verifier.

Tests:
1. Forensic codeword recovery from leaked PDF.
2. Accurate correlation scoring against ledger sessions (Alice vs Bob).
3. Evidence bundle compilation.
4. Standalone offline verification of evidence bundle.
5. Immediate rejection of tampered evidence bundles (signature, hash, or Merkle tampering).
"""

import os
import copy
import json
import pytest
import fitz

from seal.pqc_adapter import MLDSA65, MLKEM768, b64_decode, b64_encode
from chronicle.ledger import Ledger
from warden.policy import PolicyEngine
from warden.custody import KeyCustodyManager
from seal.container import ContainerBuilder
from bridge.session import RecipientCryptoSession
from hound.attribution import ForensicAccuser
from hound.evidence import EvidenceBundleBuilder
from hound.verify import verify_evidence_bundle


@pytest.fixture
def forensics_env(tmp_path):
    """Set up complete environment with 2 enrolled recipients and 1 decrypted leaked document."""
    test_dir = str(tmp_path / "forensics_env")
    os.makedirs(test_dir, exist_ok=True)
    db_path = os.path.join(test_dir, "forensics_ledger.db")
    keys_dir = os.path.join(test_dir, "client_keys")
    wm_seed = b"FORENSICS_TEST_WM_SEED_2026"

    ledger = Ledger(db_path=db_path, node_id="VAL_NODE_01")
    policy = PolicyEngine(ledger=ledger)
    custody = KeyCustodyManager(ledger=ledger, node_id="VAL_NODE_01", node_share_index=1, wm_master_seed=wm_seed)

    # 1. Enroll Alice and Bob
    alice = RecipientCryptoSession(recipient_id="ALICE", keys_dir=keys_dir)
    bob = RecipientCryptoSession(recipient_id="BOB", keys_dir=keys_dir)

    for r in [alice, bob]:
        p, sig = r.get_enroll_payload()
        entry = {"entry_type": "ENROLL", "payload": p, "signature": b64_decode(sig), "signer_id": r.recipient_id}
        ledger.commit_block([entry], proposer_id="VAL_NODE_01", validator_sigs={"VAL_NODE_01": b"sig"})

    # 2. Distribute 6-block document
    sample_pdf = os.path.join(test_dir, "source.pdf")
    doc = fitz.open()
    page = doc.new_page()
    for idx, text in enumerate([
        "Record Line 1: Prime Minister Office Briefing Paper",
        "Record Line 2: Inter-Services Quantum Safe Enclave Requirements",
        "Record Line 3: Department of Space Forensic Provenance Audit",
        "Record Line 4: Ministry of Defence High-Assurance Channels",
        "Record Line 5: National Critical Infrastructure Protection",
        "Record Line 6: Section 63 BSA Non-Repudiation Certificate"
    ]):
        page.insert_text((72, 80 + idx * 40), text, fontsize=11)
    doc.save(sample_pdf)
    doc.close()

    sender_vk, sender_sk = MLDSA65.keygen()
    c_bytes, man, shares = ContainerBuilder.build_container(
        pdf_path=sample_pdf,
        doc_id="DOC_CABINET_001",
        recipients_map={"ALICE": alice.kem_pk, "BOB": bob.kem_pk},
        sender_sk=sender_sk,
        lines_per_block=1
    )

    man_entry = {"entry_type": "MANIFEST", "payload": man["payload"], "signature": b64_decode(man["signature_b64"]), "signer_id": "SENDER"}
    ledger.commit_block([man_entry], proposer_id="VAL_NODE_01", validator_sigs={"VAL_NODE_01": b"sig"})
    for s_idx in [1, 2, 3]:
        ledger.store_key_shares("DOC_CABINET_001", shares[s_idx])

    # 3. Alice decrypts
    _, a_meta, a_blocks = alice.unwrap_container(c_bytes)
    a_req, a_sig, a_dk = alice.create_decrypt_request("DOC_CABINET_001")
    a_entry = {"entry_type": "DECRYPT_REQUEST", "payload": a_req, "signature": b64_decode(a_sig), "signer_id": "ALICE"}
    a_commit = ledger.commit_block([a_entry], proposer_id="VAL_NODE_01", validator_sigs={"VAL_NODE_01": b"sig"})
    a_hash = a_commit["entry_hashes"][0]

    custody_nodes = [
        KeyCustodyManager(ledger=ledger, node_id=f"VAL_NODE_0{i}", node_share_index=i, wm_master_seed=wm_seed)
        for i in [1, 2, 3]
    ]
    a_releases = [
        cn.release_shares_for_committed_session("DOC_CABINET_001", a_hash, b64_decode(a_req["ephemeral_ml_kem_pk"]), 6)
        for cn in custody_nodes
    ]
    alice_pdf = alice.reconstruct_and_assemble("DOC_CABINET_001", a_meta, a_blocks, a_releases, a_dk)

    # 4. Bob decrypts
    _, b_meta, b_blocks = bob.unwrap_container(c_bytes)
    b_req, b_sig, b_dk = bob.create_decrypt_request("DOC_CABINET_001")
    b_entry = {"entry_type": "DECRYPT_REQUEST", "payload": b_req, "signature": b64_decode(b_sig), "signer_id": "BOB"}
    b_commit = ledger.commit_block([b_entry], proposer_id="VAL_NODE_01", validator_sigs={"VAL_NODE_01": b"sig"})
    b_hash = b_commit["entry_hashes"][0]

    b_releases = [
        cn.release_shares_for_committed_session("DOC_CABINET_001", b_hash, b64_decode(b_req["ephemeral_ml_kem_pk"]), 6)
        for cn in custody_nodes
    ]
    bob_pdf = bob.reconstruct_and_assemble("DOC_CABINET_001", b_meta, b_blocks, b_releases, b_dk)

    yield {
        "ledger": ledger,
        "wm_seed": wm_seed,
        "alice_pdf": alice_pdf,
        "bob_pdf": bob_pdf,
        "test_dir": test_dir
    }


def test_forensic_accusation_and_offline_verification(forensics_env):
    env = forensics_env
    ledger = env["ledger"]
    wm_seed = env["wm_seed"]
    alice_pdf = env["alice_pdf"]

    accuser = ForensicAccuser(ledger=ledger, wm_master_seed=wm_seed)

    # Ingest Alice's copy as leaked document
    result = accuser.accuse_leaked_document(
        leaked_pdf_path_or_bytes=alice_pdf,
        doc_id="DOC_CABINET_001",
        total_blocks=6,
        lines_per_block=1
    )

    # Verify Accusation Outcome
    assert result.top_candidate.recipient_id == "ALICE"
    assert result.top_candidate.match_count == 6
    assert result.top_candidate.match_percentage == 100.0
    assert result.separation_margin_bits > 0
    assert result.false_accusation_probability < 0.10  # For M=6; for M=420 blocks it is < 1e-20

    # Build Evidence Bundle
    bundle_path = os.path.join(env["test_dir"], "EVIDENCE_BUNDLE.json")
    bundle = EvidenceBundleBuilder.build_bundle(result, ledger=ledger, output_file=bundle_path)
    assert os.path.exists(bundle_path)

    # Standalone Offline Verification of Evidence Bundle
    is_valid, audit_log = verify_evidence_bundle(bundle)
    assert is_valid is True, "\n".join(audit_log)


def test_tampered_bundle_rejection(forensics_env):
    env = forensics_env
    ledger = env["ledger"]
    accuser = ForensicAccuser(ledger=ledger, wm_master_seed=env["wm_seed"])

    result = accuser.accuse_leaked_document(env["alice_pdf"], "DOC_CABINET_001", total_blocks=6, lines_per_block=1)
    bundle = EvidenceBundleBuilder.build_bundle(result, ledger=ledger)

    # 1. Tamper recipient signature
    b_tamper_sig = copy.deepcopy(bundle)
    raw_sig = bytearray(b64_decode(b_tamper_sig["session_provenance"]["recipient_ml_dsa_signature"]))
    raw_sig[50] ^= 0xFF
    b_tamper_sig["session_provenance"]["recipient_ml_dsa_signature"] = b64_encode(bytes(raw_sig))
    is_val, _ = verify_evidence_bundle(b_tamper_sig)
    assert is_val is False, "Tampered signature must be rejected!"

    # 2. Tamper payload field (e.g. change nonce or recipient)
    b_tamper_payload = copy.deepcopy(bundle)
    b_tamper_payload["session_provenance"]["decrypt_request_payload"]["recipient_id"] = "CHARLIE"
    is_val2, _ = verify_evidence_bundle(b_tamper_payload)
    assert is_val2 is False, "Altered payload must break signature or entry hash!"

    # 3. Tamper Merkle root
    b_tamper_merkle = copy.deepcopy(bundle)
    b_tamper_merkle["ledger_proof"]["merkle_root"] = "0" * 64
    is_val3, _ = verify_evidence_bundle(b_tamper_merkle)
    assert is_val3 is False, "Tampered Merkle root must be rejected!"
