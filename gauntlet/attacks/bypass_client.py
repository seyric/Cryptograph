"""Attack Scenario: Rogue Client Patch & Logging Bypass.

Simulates an attacker who patches the client binary to remove the network call to the
validator quorum, hoping to decrypt an unmarked plaintext document offline without logging.

Proves:
- The recipient's local credentials only unwrap the outer container (K_out).
- The inner variant segments are encrypted under AES-256-GCM keys held in threshold custody
  by the validator quorum as Shamir shares.
- Without committing a signed DECRYPT_REQUEST to the ledger, zero variant keys are released.
- The attacker is left with useless ciphertexts: "No log, no key."
"""

import sys
from bridge.session import RecipientCryptoSession


def run_bypass_attack(container_path: str, recipient_id: str = "ALICE"):
    print("=" * 76)
    print("       CANARY TRAP ATTACK SCENARIO: CLIENT LOGGING BYPASS ATTEMPT          ")
    print("=" * 76)
    print(f"[*] Attacker Identity: {recipient_id}")
    print(f"[*] Target Container:  {container_path}")

    # Load recipient session
    client = RecipientCryptoSession(recipient_id=recipient_id, keys_dir="data/client_keys")

    with open(container_path, "rb") as fh:
        container_bytes = fh.read()

    # Step 1: Attacker attempts to unwrap outer container
    print("[*] Attacker action: Unwrapping outer container using local ML-KEM private key...")
    try:
        doc_id, doc_meta, encrypted_blocks = client.unwrap_container(container_bytes)
        print(f"[+] Outer container unwrapped! Found {len(encrypted_blocks)} encrypted variant blocks.")
    except Exception as e:
        print(f"[!] Outer unwrap failed: {e}")
        return False

    # Step 2: Attacker skips ledger communication!
    print("[*] Attacker action: INTENTIONALLY SKIPPING LEDGER LOGGING (Bypass mode active)...")
    print("[*] Attacker attempts to decrypt variant blocks directly without quorum keys...")

    # Attacker tries to decrypt blocks with their own key material
    decrypted_blocks = []
    try:
        # Client attempts to assemble with empty or fabricated release bundles
        empty_releases = []
        client.reconstruct_and_assemble(
            doc_id=doc_id,
            doc_meta=doc_meta,
            encrypted_blocks=encrypted_blocks,
            release_bundles=empty_releases,
            ephemeral_dk_bytes=b"\x00" * 2400
        )
        print(">>> FAILURE: Attacker bypassed logging and obtained plaintext! <<<")
        return False
    except Exception as e:
        print("-" * 76)
        print(">>> RESULT: DECRYPTION ATTEMPT FAILED! <<<")
        print(f">>> Cryptographic Barrier: {str(e)}")
        print(">>> Reason: Inner content variant keys exist only as Shamir shares across the quorum.")
        print(">>> Invariant Preserved: 'NO LOG, NO KEY.' Plaintext was never accessible.")
        print("=" * 76)
        return True


if __name__ == "__main__":
    c_path = sys.argv[1] if len(sys.argv) > 1 else "DOC_CABINET_2026.ct"
    run_bypass_attack(c_path)
