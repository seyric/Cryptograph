"""Hardening Test 1: Real Multi-Page Document Pipeline Test.

Validates:
1. Generation of a realistic 3-page, 24-block National Security Directive.
2. Container packaging with pre-encrypted dual variants across multiple pages.
3. Decryption sessions for Alice and Bob on multi-page layouts.
4. Textual identity check: Verifies all 3 pages contain 100.0% identical text.
5. Bit-level watermark recovery across all 3 pages.
6. Forensic correlation and Hoeffding confidence bounds on 24-block codeword.
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
from hound.attribution import ForensicAccuser


def create_realistic_multipage_pdf(filepath: str) -> int:
    """Creates a realistic 3-page government directive and returns total paragraph blocks."""
    doc = fitz.open()

    # Content structure: 8 paragraph blocks per page = 24 blocks total
    pages_content = [
        # Page 1
        [
            "NATIONAL CYBER DEFENCE DIRECTIVE 2026 - CONFIDENTIAL",
            "EXECUTIVE SUMMARY: Post-Quantum Migration Framework for Infrastructure.",
            "1.1: All designated government entities must implement post-quantum protocols.",
            "1.2: Traditional asymmetric cryptosystems like RSA and ECDSA are deprecated.",
            "1.3: Immediate implementation of NIST FIPS 203 ML-KEM-768 key encapsulation.",
            "1.4: Universal adoption of NIST FIPS 204 ML-DSA-65 digital signatures.",
            "1.5: Inter-agency distribution must be mediated by Byzantine quorums.",
            "1.6: Dynamic cryptographic watermarking shall prevent untraceable leaks."
        ],
        # Page 2
        [
            "SECTION 2: MANDATORY ATTRIBUTION AND PROVENANCE PROTOCOLS",
            "2.1: The 'No Log, No Key' invariant must be strictly enforced on hosts.",
            "2.2: Decryption variant keys remain split under threshold Shamir sharing.",
            "2.3: Plaintext representations shall never be generated unmarked.",
            "2.4: Each recipient session receives a unique micro-typographic variant.",
            "2.5: The variant assignment is evaluated via HMAC-SHA3-256 PRF from commit.",
            "2.6: The resultant word-spacing shifts are imperceptible to readers.",
            "2.7: Any attempt to bypass logging yields unusable ciphertexts."
        ],
        # Page 3
        [
            "SECTION 3: LEGAL ADMISSIBILITY UNDER SECTION 63 BSA 2023",
            "3.1: All evidence bundles generated satisfy Section 63 of BSA 2023.",
            "3.2: The immutable ledger guarantees complete chronological custody.",
            "3.3: Merkle audit proofs establish mathematical binding to block headers.",
            "3.4: In the event of unauthorized leaks, the extractor recovers codeword.",
            "3.5: Statistical correlation against access sessions isolates the leaker.",
            "3.6: Splicing attacks result in definitive attribution of all colluders.",
            "3.7: Official compliance certification signed by National Cyber Centre."
        ]
    ]

    total_blocks = 0
    for p_idx, lines in enumerate(pages_content):
        page = doc.new_page(width=595, height=842)
        y = 80
        for line in lines:
            fontsize = 13 if y == 80 else 10
            page.insert_text((60, y), line, fontsize=fontsize)
            y += 85
            total_blocks += 1

    doc.save(filepath)
    doc.close()
    return total_blocks


def test_multipage_realistic_document_pipeline(tmp_path):
    test_dir = str(tmp_path / "multipage_harness")
    os.makedirs(test_dir, exist_ok=True)
    db_path = os.path.join(test_dir, "multipage_ledger.db")
    keys_dir = os.path.join(test_dir, "keys")

    # 1. Generate realistic 3-page PDF
    source_pdf = os.path.join(test_dir, "national_directive_3page.pdf")
    total_expected_blocks = create_realistic_multipage_pdf(source_pdf)
    assert total_expected_blocks == 24

    wm_seed = b"MULTIPAGE_HARDENING_SEED_2026"
    val_vk, val_sk = MLDSA65.keygen()
    sender_vk, sender_sk = MLDSA65.keygen()

    ledger = Ledger(db_path=db_path, node_id="VAL_01")
    policy = PolicyEngine(ledger=ledger)
    custody_nodes = [
        KeyCustodyManager(ledger=ledger, node_id=f"VAL_0{i}", node_share_index=i, wm_master_seed=wm_seed)
        for i in [1, 2, 3]
    ]

    # 2. Enroll Alice and Bob
    alice = RecipientCryptoSession(recipient_id="ALICE_DEPT_A", keys_dir=keys_dir)
    bob = RecipientCryptoSession(recipient_id="BOB_DEPT_B", keys_dir=keys_dir)

    for rec in [alice, bob]:
        payload, sig_b64 = rec.get_enroll_payload()
        is_val, err = policy.validate_enroll_request(payload, b64_decode(sig_b64))
        assert is_val, err
        entry = {
            "entry_type": "ENROLL",
            "payload": payload,
            "signature": b64_decode(sig_b64),
            "signer_id": rec.recipient_id
        }
        ledger.commit_block([entry], proposer_id="VAL_01", validator_sigs={"VAL_01": b"sig"})

    # 3. Package Multi-Page Container with 24 Blocks
    doc_id = "DOC_NAT_DIRECTIVE_2026"
    recipients_map = {
        "ALICE_DEPT_A": alice.kem_pk,
        "BOB_DEPT_B": bob.kem_pk
    }

    container_bytes, signed_manifest, node_shares = ContainerBuilder.build_container(
        pdf_path=source_pdf,
        doc_id=doc_id,
        recipients_map=recipients_map,
        sender_sk=sender_sk,
        lines_per_block=1  # 1 paragraph per block -> 24 blocks
    )

    # Commit Manifest
    man_entry = {
        "entry_type": "MANIFEST",
        "payload": signed_manifest["payload"],
        "signature": b64_decode(signed_manifest["signature_b64"]),
        "signer_id": "MINISTRY_HQ"
    }
    ledger.commit_block([man_entry], proposer_id="VAL_01", validator_sigs={"VAL_01": b"sig"})

    # Deposit Key Shares across 3 custody nodes
    for idx in [1, 2, 3]:
        ledger.store_key_shares(doc_id, node_shares[idx])

    # 4. Alice Multi-Page Decryption
    d_id, a_meta, a_blocks = alice.unwrap_container(container_bytes)
    assert len(a_blocks) == 24, f"Expected 24 blocks, got {len(a_blocks)}"

    a_req, a_sig, a_eph_dk = alice.create_decrypt_request(doc_id)
    req_entry_a = {
        "entry_type": "DECRYPT_REQUEST",
        "payload": a_req,
        "signature": b64_decode(a_sig),
        "signer_id": alice.recipient_id
    }
    a_commit = ledger.commit_block([req_entry_a], proposer_id="VAL_01", validator_sigs={"VAL_01": b"sig"})
    a_session_hash = a_commit["entry_hashes"][0]

    a_releases = [
        c.release_shares_for_committed_session(
            doc_id=doc_id,
            session_entry_hash_hex=a_session_hash,
            ephemeral_ml_kem_pk_bytes=b64_decode(a_req["ephemeral_ml_kem_pk"]),
            total_blocks=24
        )
        for c in custody_nodes
    ]

    alice_pdf_bytes = alice.reconstruct_and_assemble(
        doc_id=doc_id,
        doc_meta=a_meta,
        encrypted_blocks=a_blocks,
        release_bundles=a_releases,
        ephemeral_dk_bytes=a_eph_dk
    )

    # 5. Bob Multi-Page Decryption
    _, b_meta, b_blocks = bob.unwrap_container(container_bytes)
    b_req, b_sig, b_eph_dk = bob.create_decrypt_request(doc_id)
    req_entry_b = {
        "entry_type": "DECRYPT_REQUEST",
        "payload": b_req,
        "signature": b64_decode(b_sig),
        "signer_id": bob.recipient_id
    }
    b_commit = ledger.commit_block([req_entry_b], proposer_id="VAL_01", validator_sigs={"VAL_01": b"sig"})
    b_session_hash = b_commit["entry_hashes"][0]

    b_releases = [
        c.release_shares_for_committed_session(
            doc_id=doc_id,
            session_entry_hash_hex=b_session_hash,
            ephemeral_ml_kem_pk_bytes=b64_decode(b_req["ephemeral_ml_kem_pk"]),
            total_blocks=24
        )
        for c in custody_nodes
    ]

    bob_pdf_bytes = bob.reconstruct_and_assemble(
        doc_id=doc_id,
        doc_meta=b_meta,
        encrypted_blocks=b_blocks,
        release_bundles=b_releases,
        ephemeral_dk_bytes=b_eph_dk
    )

    # 6. Verify Full 3-Page Layout and Text Integrity
    doc_orig = fitz.open(source_pdf)
    doc_alice = fitz.open(stream=alice_pdf_bytes, filetype="pdf")
    doc_bob = fitz.open(stream=bob_pdf_bytes, filetype="pdf")

    assert len(doc_alice) == 3, f"Alice PDF should have 3 pages, got {len(doc_alice)}"
    assert len(doc_bob) == 3, f"Bob PDF should have 3 pages, got {len(doc_bob)}"

    # Check text across all 3 pages
    for p in range(3):
        orig_text = doc_orig[p].get_text().strip()
        alice_text = doc_alice[p].get_text().strip()
        bob_text = doc_bob[p].get_text().strip()

        assert alice_text == orig_text, f"Page {p+1} Alice text mismatch"
        assert bob_text == orig_text, f"Page {p+1} Bob text mismatch"
        assert alice_text == bob_text, f"Page {p+1} Alice and Bob text must be 100% identical"

    # Verify binary streams differ
    assert alice_pdf_bytes != bob_pdf_bytes, "Binary streams must differ due to distinct fingerprints"

    # 7. Extract Watermark from 3-Page PDF & Test Attribution
    expected_alice_cw = generate_codeword_bits(wm_seed, bytes.fromhex(a_session_hash), 24)
    expected_bob_cw = generate_codeword_bits(wm_seed, bytes.fromhex(b_session_hash), 24)

    recovered_a_cw, _ = WatermarkExtractor.extract_from_pdf(alice_pdf_bytes, total_expected_blocks=24, lines_per_block=1)
    recovered_b_cw, _ = WatermarkExtractor.extract_from_pdf(bob_pdf_bytes, total_expected_blocks=24, lines_per_block=1)

    assert recovered_a_cw == expected_alice_cw, f"Alice 24-block recovery failed: {recovered_a_cw} != {expected_alice_cw}"
    assert recovered_b_cw == expected_bob_cw, f"Bob 24-block recovery failed: {recovered_b_cw} != {expected_bob_cw}"

    # 8. Run Forensic Accuser on Alice's 3-Page PDF
    accuser = ForensicAccuser(ledger=ledger, wm_master_seed=wm_seed)
    report = accuser.accuse_leaked_document(
        leaked_pdf_path_or_bytes=alice_pdf_bytes,
        doc_id=doc_id,
        total_blocks=24,
        lines_per_block=1
    )

    assert report.top_candidate.recipient_id == "ALICE_DEPT_A"
    assert report.top_candidate.match_count == 24
    assert report.top_candidate.match_percentage == 100.0
    # On 24 blocks, delta from mean is (24 - 12) = 12. Exponent = -2 * 144 / 24 = -12. false_prob = exp(-12) = 6.14e-6
    assert report.false_accusation_probability < 1e-5
    assert report.separation_margin_bits >= 6


if __name__ == "__main__":
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        test_multipage_realistic_document_pipeline(pathlib.Path(td))
        print("[+] Hardening Test 1 (Real Multi-Page Document Pipeline) PASSED cleanly!")
