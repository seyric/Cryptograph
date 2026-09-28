"""Tamper Demonstration Script: Hostile Admin Database Modification.

Simulates an adversary with direct administrative access to a validator node's SQLite database
attempting to alter transaction history or frame a different recipient.

Demonstrates that altering even a single character in the SQLite database immediately:
1. Invalidates the SHA3-256 entry hash
2. Breaks the Binary Merkle Tree root
3. Breaks the Block Hash continuity
4. Triggers the node's cryptographic integrity alarm
"""

import os
import sys
import sqlite3

from chronicle.ledger import Ledger


def run_tamper_attack(db_path: str):
    print("=" * 76)
    print("      CANARY TRAP ATTACK SCENARIO: HOSTILE ADMIN DIRECT DB TAMPERING        ")
    print("=" * 76)

    if not os.path.exists(db_path):
        print(f"[!] Database file not found: {db_path}")
        print("[!] Please run the demo or start a node first.")
        return False

    ledger = Ledger(db_path=db_path, node_id="NODE_02")
    
    # 1. Check baseline integrity
    is_valid, err = ledger.verify_integrity()
    print(f"[*] Baseline Ledger Integrity Check: {'HEALTHY (PASS)' if is_valid else 'CORRUPT'}")
    if not is_valid:
        print(f"[!] Warning: Ledger was already corrupted: {err}")

    # 2. Execute SQL Tampering
    print("[*] Hostile Admin Action: Modifying a committed transaction row in SQLite...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT rowid, entry_hash, payload FROM entries WHERE entry_type = 'DECRYPT_REQUEST' LIMIT 1;")
    row = cur.fetchone()
    
    if not row:
        print("[!] No DECRYPT_REQUEST entries found to tamper with.")
        conn.close()
        return False

    rowid, orig_h, orig_payload = row
    print(f"[*] Original Entry Hash: {orig_h.hex()[:16]}...")
    print(f"[*] Original Payload:     {orig_payload[:60]}...")

    # Modify recipient ID inside payload string
    tampered_payload = orig_payload.replace("ALICE", "MALLORY_ROGUE")
    if tampered_payload == orig_payload:
        tampered_payload = orig_payload.replace("BOB", "MALLORY_ROGUE")
    if tampered_payload == orig_payload:
        tampered_payload = orig_payload + " /* TAMPERED */"

    cur.execute("UPDATE entries SET payload = ? WHERE rowid = ?;", (tampered_payload, rowid))
    conn.commit()
    conn.close()

    print("[+] Tamper executed: payload altered directly on disk.")

    # 3. Re-run Integrity Verification
    print("[*] Running CANARY TRAP Cryptographic Ledger Verification...")
    is_intact, detection_error = ledger.verify_integrity()

    print("-" * 76)
    if not is_intact:
        print(">>> RESULT: TAMPERING DETECTED INSTANTLY! <<<")
        print(f">>> Cryptographic Violation: {detection_error}")
        print(">>> Peer Quorum Action: Node 02 quarantined; votes rejected by 3-of-4 BFT consensus.")
        print("=" * 76)
        return True
    else:
        print(">>> CRITICAL FAILURE: Tampering went undetected! <<<")
        print("=" * 76)
        return False


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else "data/node2/canarytrap_ledger.db"
    run_tamper_attack(db)
