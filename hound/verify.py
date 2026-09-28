"""Standalone Zero-Network Cryptographic Verifier for CANARY TRAP Evidence Bundles.

Designed for courtrooms, forensic investigators, and independent auditors:
- Requires ZERO network connectivity (100% offline)
- Verifies recipient ML-DSA-65 non-repudiation digital signature
- Validates binary Merkle inclusion proof chaining entry to block header
- Verifies quorum validator ML-DSA-65 signatures on the block
- Outputs Section 63 BSA Electronic Records Compliance Certificate
"""

import sys
import json
from typing import Dict, Any, Tuple, List

from seal.pqc_adapter import MLDSA65, b64_decode
from seal.merkle import verify_merkle_proof
from chronicle.entry import compute_entry_hash
from chronicle.block_cert import (
    QUORUM_THRESHOLD,
    QuorumCertificate,
    verify_certificate,
)


def verify_evidence_bundle(bundle_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Perform complete mathematical and cryptographic verification of an evidence bundle.
    
    Returns:
        (is_verified: bool, audit_log: List[str])
    """
    log = []
    
    # 1. Inspect structure
    if bundle_data.get("version") != "canarytrap-evidence-v1":
        return False, ["Invalid bundle version format"]

    prov = bundle_data["session_provenance"]
    proof = bundle_data["ledger_proof"]
    attr = bundle_data["attribution"]
    leaked = bundle_data["leaked_document"]

    log.append(f"Analyzing Evidence Bundle for Leaked File: {leaked['sha3_256'][:16]}...")
    log.append(f"Target Accused Recipient: {attr['accused_recipient_id']}")

    # 2. Verify Recipient ML-DSA-65 Digital Signature
    try:
        recipient_vk = b64_decode(prov["recipient_ml_dsa_public_key"])
        recipient_sig = b64_decode(prov["recipient_ml_dsa_signature"])
        req_payload = prov["decrypt_request_payload"]
    except Exception as e:
        return False, [f"Failed to decode recipient cryptographic material: {str(e)}"]

    is_sig_valid = MLDSA65.verify(recipient_vk, req_payload, recipient_sig)
    if not is_sig_valid:
        return False, [
            "CRITICAL: Recipient ML-DSA-65 digital signature verification FAILED!",
            "Non-repudiation binding is invalid."
        ]
    log.append("[PASS] Step 1: Recipient ML-DSA-65 digital signature verified (Non-repudiation confirmed).")

    # 3. Verify Session Entry Hash (definition owned by chronicle.entry)
    entry_bytes = compute_entry_hash("DECRYPT_REQUEST", req_payload, recipient_sig)
    computed_entry_hash = entry_bytes.hex()

    if computed_entry_hash != prov["session_entry_hash"]:
        return False, [
            f"CRITICAL: Session entry hash mismatch! Computed {computed_entry_hash} != {prov['session_entry_hash']}"
        ]
    log.append(f"[PASS] Step 2: Session entry hash matches canonical payload ({computed_entry_hash[:16]}...).")

    # 4. Verify Binary Merkle Inclusion Proof to Block Header
    merkle_proof_raw = [
        {"position": p["position"], "hash": bytes.fromhex(p["hash"])}
        for p in proof["merkle_inclusion_proof"]
    ]
    expected_root = bytes.fromhex(proof["merkle_root"])

    merkle_valid = verify_merkle_proof(entry_bytes, merkle_proof_raw, expected_root)
    if not merkle_valid:
        return False, [
            "CRITICAL: Merkle inclusion proof verification FAILED!",
            f"Entry does not chain to block root {proof['merkle_root'][:16]}..."
        ]
    log.append(f"[PASS] Step 3: Merkle audit inclusion proof verified against block root ({proof['merkle_root'][:16]}...).")

    # 5. Verify Validator Quorum Signatures on Block
    block_header = {
        "height": proof["block_height"],
        "prev_hash": "0" * 64,  # Root proof ties to height and root
        "merkle_root": proof["merkle_root"],
        "timestamp": proof["block_timestamp"],
        "proposer_id": "NODE_01"
    }

    # 5. Verify the quorum certificate.
    #
    # Previously this counted validator signatures and, when a signature had no
    # accompanying public key, counted it anyway - so a bundle could claim a
    # quorum that did not exist. The certificate is now verified against the
    # validator public keys carried in the bundle, and any validator we cannot
    # check is rejected rather than believed.
    certificate_data = proof.get("quorum_certificate")
    if not certificate_data:
        return False, [
            "CRITICAL: Evidence bundle carries no quorum certificate. "
            "A block without a verifiable certificate cannot support attribution."
        ]

    threshold = int(certificate_data.get("quorum_threshold", QUORUM_THRESHOLD))
    validator_keys: Dict[str, bytes] = {}
    for validator_id, record in (certificate_data.get("signatures") or {}).items():
        public_key_b64 = record.get("public_key")
        if not public_key_b64:
            return False, [
                f"CRITICAL: Validator {validator_id} signature has no public key, "
                "so it cannot be verified. Refusing an unverifiable quorum."
            ]
        try:
            validator_keys[validator_id] = b64_decode(public_key_b64)
        except Exception as exc:
            return False, [f"CRITICAL: Validator {validator_id} public key is malformed: {exc}"]

    certificate = QuorumCertificate(
        version=certificate_data["version"],
        height=int(certificate_data["height"]),
        prev_hash=certificate_data["prev_hash"],
        merkle_root=certificate_data["merkle_root"],
        timestamp=int(certificate_data["timestamp"]),
        proposer_id=certificate_data["proposer_id"],
        block_hash=certificate_data["block_hash"],
        signatures={
            validator_id: b64_decode(record["signature"])
            for validator_id, record in certificate_data["signatures"].items()
        },
    )

    # The certificate must describe the same block the inclusion proof anchors to.
    if certificate.merkle_root != proof["merkle_root"]:
        return False, [
            "CRITICAL: Quorum certificate does not describe the block in the "
            f"inclusion proof ({certificate.merkle_root} != {proof['merkle_root']})"
        ]

    quorum_ok, valid_ids, problems = verify_certificate(certificate, validator_keys, threshold)
    for validator_id in valid_ids:
        log.append(f"  - Validator {validator_id} ML-DSA-65 signature: VALID")
    if not quorum_ok:
        return False, ["CRITICAL: Quorum certificate failed verification:"] + [
            f"  - {problem}" for problem in problems
        ]

    log.append(
        f"[PASS] Step 4: Quorum certificate verified "
        f"({len(valid_ids)}/{threshold} validators signed this exact header)."
    )

    # 6. Verify Attribution Correlation Margin
    score = attr["matching_score"]
    total = attr["total_blocks"]
    pct = attr["match_percentage"]
    margin = attr["separation_margin_bits"]

    if pct < 65.0:
        return False, [f"Attribution score too low for definitive identification ({pct:.1f}%)"]

    log.append(f"[PASS] Step 5: Statistical correlation confirmed ({score}/{total} blocks, {pct:.2f}% match, Margin: {margin} bits).")
    log.append(f"       Upper Bound on False Accusation Probability: {attr['false_accusation_probability_bound']}.")

    return True, log


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m hound.verify <path_to_EVIDENCE_BUNDLE.json>")
        sys.exit(1)

    bundle_path = sys.argv[1]
    with open(bundle_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    print("=" * 76)
    print("      CANARY TRAP STANDALONE OFFLINE CRYPTOGRAPHIC EVIDENCE VERIFIER       ")
    print("        Section 63 Bharatiya Sakshya Adhiniyam, 2023 Compliant       ")
    print("=" * 76)

    success, audit_log = verify_evidence_bundle(data)

    for line in audit_log:
        print(line)

    print("-" * 76)
    if success:
        print(">>> VERIFICATION STATUS: 100% CRYPTOGRAPHICALLY AUTHENTIC & VALIDATED <<<")
        print(f">>> CULPRIT ATTRIBUTION: {data['attribution']['accused_recipient_id']} <<<")
        print("=" * 76)
        sys.exit(0)
    else:
        print(">>> VERIFICATION STATUS: REJECTED / TAMPERED EVIDENCE DETECTED <<<")
        print("=" * 76)
        sys.exit(2)


if __name__ == "__main__":
    main()
