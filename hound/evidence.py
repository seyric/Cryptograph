"""Cryptographic Evidence Bundle Builder for CANARY TRAP.

Compiles a self-contained Section 63 BSA Evidence Bundle for judicial review:
- Leaked document cryptographic hash
- Recovered watermark bits and correlation stats
- Accused recipient identity and non-repudiation signature
- Merkle audit inclusion proof connecting request to block header
- Quorum validator ML-DSA signatures on the block
"""

import json
from typing import Dict, Any, Optional

from .attribution import AccusationResult
from chronicle.ledger import Ledger
from chronicle.block_cert import CERTIFICATE_VERSION, QUORUM_THRESHOLD
from seal.pqc_adapter import b64_encode


class EvidenceBundleBuilder:
    """Builds self-contained verifiable evidence bundles."""

    @classmethod
    def build_bundle(
        cls,
        accusation: AccusationResult,
        ledger: Ledger,
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a complete EVIDENCE_BUNDLE dictionary and optionally save to file.
        
        Args:
            accusation: AccusationResult from ForensicAccuser.
            ledger: Ledger instance to pull proofs and signatures.
            output_file: Optional path to write JSON bundle.
            
        Returns:
            Dict matching EVIDENCE_BUNDLE specification.
        """
        top = accusation.top_candidate
        session_entry_hash = top.session_entry_hash

        # Pull entry record
        entry_record = ledger.get_entry(session_entry_hash)
        if not entry_record:
            raise RuntimeError(f"Session entry {session_entry_hash} not found in ledger")

        # Pull Merkle inclusion proof
        merkle_info = ledger.get_merkle_proof(session_entry_hash)
        if not merkle_info:
            raise RuntimeError(f"Failed to generate Merkle proof for {session_entry_hash}")

        # Pull recipient's enrolled public key
        with ledger._get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT ml_dsa_public_key FROM enrolled_identities WHERE recipient_id = ?;", (top.recipient_id,))
            id_row = cur.fetchone()
            recipient_dsa_pk = id_row["ml_dsa_public_key"] if id_row else b""

        bundle = {
            "version": "canarytrap-evidence-v1",
            "leaked_document": {
                "sha3_256": accusation.leaked_file_hash,
                "total_blocks_analyzed": accusation.total_blocks_analyzed
            },
            "recovered_codeword": {
                "codeword_bits": "".join(str(b) for b in accusation.recovered_codeword),
                "match_percentage": top.match_percentage,
                # Disclose how the codeword was obtained. "content_stream" reads
                # the writer's own Tw operators, so it is a weaker claim than
                # "geometric", which measures the rendered document.
                "extraction_strategy": accusation.extraction_strategy,
                "mean_confidence": round(accusation.extraction_confidence, 4),
            },
            "attribution": {
                "accused_recipient_id": top.recipient_id,
                "matching_score": top.match_count,
                "total_blocks": top.total_blocks,
                "match_percentage": top.match_percentage,
                "runner_up_score": accusation.runner_up.match_count if accusation.runner_up else None,
                "separation_margin_bits": accusation.separation_margin_bits,
                "false_accusation_probability_bound": f"{accusation.false_accusation_probability:.2e}"
            },
            "session_provenance": {
                "session_entry_hash": session_entry_hash,
                "decrypt_request_payload": entry_record["payload"],
                "recipient_ml_dsa_signature": entry_record["signature"],
                "recipient_ml_dsa_public_key": b64_encode(recipient_dsa_pk)
            },
            "ledger_proof": {
                "block_height": merkle_info["block_height"],
                "block_hash": merkle_info["block_hash"],
                "block_timestamp": entry_record["block_timestamp"],
                "merkle_root": merkle_info["merkle_root"],
                "merkle_inclusion_proof": merkle_info["proof"],
                "validator_signatures": merkle_info["validator_signatures"],
                # The quorum certificate: the header fields plus every validator
                # signature over exactly those bytes, each with its public key so
                # an offline verifier can check agreement instead of counting it.
                "quorum_certificate": {
                    "version": CERTIFICATE_VERSION,
                    "height": merkle_info["block_height"],
                    "prev_hash": merkle_info["prev_hash"],
                    "merkle_root": merkle_info["merkle_root"],
                    "timestamp": merkle_info["block_timestamp"],
                    "proposer_id": merkle_info["proposer_id"],
                    "block_hash": merkle_info["block_hash"],
                    "signatures": {
                        s["validator_id"]: {
                            "signature": s["signature"],
                            "public_key": s.get("public_key"),
                        }
                        for s in merkle_info["validator_signatures"]
                    },
                    "quorum_threshold": QUORUM_THRESHOLD,
                },
            }
        }

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2)

        return bundle
