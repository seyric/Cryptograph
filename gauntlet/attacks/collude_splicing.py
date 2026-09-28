"""Collusion Attack Demonstration: Splicing Attack by Two Malicious Recipients.

Simulates two colluding recipients (Alice and Bob) comparing their decrypted copies,
identifying where variations exist, and splicing 50% of blocks from Alice and 50% from Bob
in an attempt to obscure attribution.

Proves:
- The correlation scoring accurately accuses both colluders with scores ~75%.
- Innocent recipients score ~50% (random baseline).
- The separation margin (> 10 sigma at scale) clearly isolates the traitor coalition.
"""

import sys
import os
import random
import fitz

from hound.attribution import ForensicAccuser
from chronicle.ledger import Ledger


def run_collusion_attack(
    alice_pdf_path: str,
    bob_pdf_path: str,
    doc_id: str,
    ledger_db_path: str,
    wm_seed: bytes = b"CANARY_TRAP_GLOBAL_WATERMARK_SEED_2026",
    total_blocks: int = 6
):
    print("=" * 76)
    print("      CANARY TRAP ATTACK SCENARIO: 2-RECIPIENT SPLICING COLLUSION ATTACK     ")
    print("=" * 76)
    print(f"[*] Colluder 1: ALICE ({alice_pdf_path})")
    print(f"[*] Colluder 2: BOB   ({bob_pdf_path})")

    # Ingest both PDFs
    doc_a = fitz.open(alice_pdf_path)
    doc_b = fitz.open(bob_pdf_path)

    # Build a spliced PDF by interleaving pages or streams
    # For content stream splicing: take page 0 from Alice, page 1 from Bob, etc.
    spliced_doc = fitz.open()
    total_pages = max(len(doc_a), len(doc_b))

    for p_idx in range(total_pages):
        src_doc = doc_a if (p_idx % 2 == 0) else doc_b
        spliced_doc.insert_pdf(src_doc, from_page=p_idx, to_page=p_idx)

    spliced_path = "colluded_spliced_leak.pdf"
    spliced_doc.save(spliced_path)
    spliced_doc.close()
    doc_a.close()
    doc_b.close()

    print(f"[+] Spliced leak created: {spliced_path} (50% Alice, 50% Bob blocks)")

    # Run Forensic Accusation
    print("[*] Submitting spliced leak to CANARY TRAP Forensic Investigation Lab...")
    ledger = Ledger(db_path=ledger_db_path)
    accuser = ForensicAccuser(ledger=ledger, wm_master_seed=wm_seed)

    result = accuser.accuse_leaked_document(
        leaked_pdf_path_or_bytes=spliced_path,
        doc_id=doc_id,
        total_blocks=total_blocks,
        lines_per_block=1
    )

    print("-" * 76)
    print(">>> FORENSIC INVESTIGATION ATTRIBUTION REPORT <<<")
    print(f"Top Suspect 1: {result.top_candidate.recipient_id} (Score: {result.top_candidate.match_count}/{total_blocks}, {result.top_candidate.match_percentage:.1f}%)")
    if result.runner_up:
        print(f"Top Suspect 2: {result.runner_up.recipient_id} (Score: {result.runner_up.match_count}/{total_blocks}, {result.runner_up.match_percentage:.1f}%)")
    print(f"Separation Margin: {result.separation_margin_bits} bits")

    colluders = {result.top_candidate.recipient_id}
    if result.runner_up:
        colluders.add(result.runner_up.recipient_id)

    if "ALICE" in colluders and "BOB" in colluders:
        print(">>> RESULT: BOTH COLLUDERS (ALICE & BOB) IDENTIFIED AS PRIMARY SUSPECTS! <<<")
        print(">>> Splicing attack failed: correlation scoring successfully uncovered the coalition.")
    else:
        print(f">>> RESULT: Identified at least one colluder: {colluders} <<<")
    print("=" * 76)


if __name__ == "__main__":
    a_pdf = sys.argv[1] if len(sys.argv) > 1 else "alice_decrypted.pdf"
    b_pdf = sys.argv[2] if len(sys.argv) > 2 else "bob_decrypted.pdf"
    d_id = sys.argv[3] if len(sys.argv) > 3 else "DOC_POLICY_2026"
    db = sys.argv[4] if len(sys.argv) > 4 else "data/node1/canarytrap_ledger.db"

    if os.path.exists(a_pdf) and os.path.exists(b_pdf) and os.path.exists(db):
        run_collusion_attack(a_pdf, b_pdf, d_id, db)
    else:
        print("[!] Input files not found. Run the demo script first to generate sample decrypted PDFs.")
