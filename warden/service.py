"""FastAPI Validator Node Service for CANARY TRAP.

Autonomous post-quantum Byzantine validator node providing:
- Identity enrollment
- Document manifest registration and key custody
- "Log Before Key" request validation and consensus commit
- Conditional release of Shamir shares for codeword-selected variants
- Merkle audit inclusion proofs and chain integrity telemetry
"""

import os
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from seal.pqc_adapter import MLDSA65, b64_encode, b64_decode, canonical_json
from chronicle.ledger import Ledger
from .policy import PolicyEngine
from .custody import KeyCustodyManager
from .consensus import BFTConsensus, QuorumNotReached
from .consensus_api import register_consensus_endpoints

app = FastAPI(title="CANARY TRAP Validator Node", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration from environment or defaults
NODE_ID = os.environ.get("CANARY_TRAP_NODE_ID", "NODE_01")
SHARE_INDEX = int(os.environ.get("CANARY_TRAP_SHARE_INDEX", "1"))
DB_PATH = os.environ.get("CANARY_TRAP_DB_PATH", f"data/{NODE_ID.lower()}/canarytrap_ledger.db")
WM_SEED = os.environ.get("CANARY_TRAP_WM_SEED", "CANARY_TRAP_DEFENCE_MASTER_SEED_2026").encode("utf-8")

# Initialize Validator ML-DSA Keypair
VALIDATOR_VK_PATH = f"data/{NODE_ID.lower()}/validator_vk.bin"
VALIDATOR_SK_PATH = f"data/{NODE_ID.lower()}/validator_sk.bin"
os.makedirs(f"data/{NODE_ID.lower()}", exist_ok=True)

if os.path.exists(VALIDATOR_VK_PATH) and os.path.exists(VALIDATOR_SK_PATH):
    with open(VALIDATOR_VK_PATH, "rb") as fh:
        VALIDATOR_VK = fh.read()
    with open(VALIDATOR_SK_PATH, "rb") as fh:
        VALIDATOR_SK = fh.read()
else:
    VALIDATOR_VK, VALIDATOR_SK = MLDSA65.keygen()
    with open(VALIDATOR_VK_PATH, "wb") as fh:
        fh.write(VALIDATOR_VK)
    with open(VALIDATOR_SK_PATH, "wb") as fh:
        fh.write(VALIDATOR_SK)

ledger = Ledger(db_path=DB_PATH, node_id=NODE_ID)
policy = PolicyEngine(ledger=ledger)
custody = KeyCustodyManager(ledger=ledger, node_id=NODE_ID, node_share_index=SHARE_INDEX, wm_master_seed=WM_SEED)
consensus = BFTConsensus(node_id=NODE_ID, ledger=ledger, validator_sk=VALIDATOR_SK, validator_vk=VALIDATOR_VK)

# The 2-phase commit endpoints live in warden/consensus_api.py.
register_consensus_endpoints(app, ledger, NODE_ID, VALIDATOR_SK, VALIDATOR_VK)


# ============================================================================
# Pydantic Wire Request Schemas
# ============================================================================

class SignedRequest(BaseModel):
    payload: Dict[str, Any]
    signature_b64: str


class KeySharesDeposit(BaseModel):
    doc_id: str
    shares: list


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/status")
def get_node_status():
    """Return live node telemetry, chain tip, and integrity health."""
    latest = ledger.get_latest_block()
    is_valid, reason = ledger.verify_integrity()
    return {
        "node_id": NODE_ID,
        "share_index": SHARE_INDEX,
        "validator_public_key": b64_encode(VALIDATOR_VK),
        "chain_tip": latest,
        "integrity_healthy": is_valid,
        "integrity_error": reason
    }


@app.post("/api/enroll")
def enroll_identity(req: SignedRequest):
    """Enroll a new recipient device public key on the immutable ledger."""
    sig_bytes = b64_decode(req.signature_b64)
    is_valid, reason = policy.validate_enroll_request(req.payload, sig_bytes)
    if not is_valid:
        raise HTTPException(status_code=400, detail=reason)

    entry = {
        "entry_type": "ENROLL",
        "payload": req.payload,
        "signature": sig_bytes,
        "signer_id": req.payload["recipient_id"]
    }

    try:
        result = consensus.propose_and_commit([entry])
    except QuorumNotReached as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {
        "status": "ENROLLED",
        "recipient_id": req.payload["recipient_id"],
        "block_height": result["height"],
        "entry_hash": result["entry_hashes"][0],
        "quorum_certified": result["quorum_certified"],
    }


@app.post("/api/manifest")
def register_manifest(req: SignedRequest):
    """Register a document distribution manifest committed to the ledger.

    The sender's signature is now verified. Previously this endpoint stored the
    signature without checking it, so an unsigned manifest could name arbitrary
    recipients for a document hash.
    """
    sig_bytes = b64_decode(req.signature_b64)
    is_valid, reason = policy.validate_manifest_request(req.payload, sig_bytes)
    if not is_valid:
        raise HTTPException(status_code=403, detail=reason)

    entry = {
        "entry_type": "MANIFEST",
        "payload": req.payload,
        "signature": sig_bytes,
        "signer_id": req.payload["sender_id"],
    }

    try:
        result = consensus.propose_and_commit([entry])
    except QuorumNotReached as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {
        "status": "MANIFEST_COMMITTED",
        "doc_id": req.payload["doc_id"],
        "block_height": result["height"],
        "entry_hash": result["entry_hashes"][0],
        "quorum_certified": result["quorum_certified"],
        "validators": result["validators"],
    }


@app.post("/api/key_shares")
def deposit_key_shares(deposit: KeySharesDeposit):
    """Store encrypted Shamir key shares for this node's custody."""
    # Shares are wrapped with this node's own key before touching the database,
    # so nothing usable is ever written in the clear.
    stored = custody.store_shares(deposit.doc_id, deposit.shares)
    return {
        "status": "SHARES_STORED",
        "doc_id": deposit.doc_id,
        "total_shares_stored": stored,
        "encrypted_at_rest": True,
    }


@app.post("/api/request_decrypt")
def request_decrypt(req: SignedRequest):
    """Log-Before-Key: verify request, commit to ledger, and release codeword variant key shares."""
    sig_bytes = b64_decode(req.signature_b64)
    is_valid, reason, identity = policy.validate_decrypt_request(req.payload, sig_bytes)
    if not is_valid:
        raise HTTPException(status_code=403, detail=reason)

    doc_id = req.payload["doc_id"]
    recipient_id = req.payload["recipient_id"]
    ephemeral_pk_bytes = b64_decode(req.payload["ephemeral_ml_kem_pk"])

    # Look up document manifest for total_blocks
    with ledger._get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT total_blocks FROM manifests WHERE doc_id = ?;", (doc_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Manifest not found for document")
        total_blocks = row["total_blocks"]

    # 1. Commit the request to a new block via consensus
    entry = {
        "entry_type": "DECRYPT_REQUEST",
        "payload": req.payload,
        "signature": sig_bytes,
        "signer_id": recipient_id
    }

    try:
        result = consensus.propose_and_commit([entry])
    except QuorumNotReached as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    session_entry_hash = result["entry_hashes"][0]

    # 2. Release key shares for codeword variants encrypted under ephemeral ML-KEM key
    release_bundle = custody.release_shares_for_committed_session(
        doc_id=doc_id,
        session_entry_hash_hex=session_entry_hash,
        ephemeral_ml_kem_pk_bytes=ephemeral_pk_bytes,
        total_blocks=total_blocks
    )

    return {
        "commit": {
            "block_height": result["height"],
            "session_entry_hash": session_entry_hash,
            "block_hash": result["block_hash"],
            "merkle_root": result["merkle_root"]
        },
        "key_release": release_bundle
    }


@app.get("/api/proof/{entry_hash}")
def get_proof(entry_hash: str):
    """Retrieve Merkle inclusion proof and validator block signatures for an entry."""
    proof = ledger.get_merkle_proof(entry_hash)
    if not proof:
        raise HTTPException(status_code=404, detail="Entry not found")
    return proof


@app.get("/api/entry/{entry_hash}")
def get_entry(entry_hash: str):
    """Retrieve entry payload and cryptographic signature."""
    record = ledger.get_entry(entry_hash)
    if not record:
        raise HTTPException(status_code=404, detail="Entry not found")
    return record


@app.get("/api/blocks")
def list_blocks(limit: int = 50):
    """List recent blocks for Audit Console."""
    with ledger._get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM blocks ORDER BY height DESC LIMIT ?;", (limit,))
        rows = cur.fetchall()
        return [
            {
                "height": r["height"],
                "prev_hash": r["prev_hash"].hex(),
                "merkle_root": r["merkle_root"].hex(),
                "timestamp": r["timestamp"],
                "proposer_id": r["proposer_id"],
                "block_hash": r["block_hash"].hex()
            }
            for r in rows
        ]


class AttributeRequest(BaseModel):
    pdf_path: Optional[str] = None
    doc_id: Optional[str] = "DEFENCE_DIRECTIVE_2026"
    total_blocks: Optional[int] = 24
    lines_per_block: Optional[int] = 1


@app.post("/api/forensics/attribute")
def attribute_leak(req: AttributeRequest):
    """Live forensic leak attribution: extract watermark from PDF and match against on-ledger sessions."""
    from hound.attribution import ForensicAccuser
    target_path = req.pdf_path or "bench_data/alice_decrypted.pdf"
    if not os.path.exists(target_path):
        candidates = [
            target_path,
            os.path.join("bench_data", os.path.basename(target_path)),
            os.path.join("data", os.path.basename(target_path)),
        ]
        for c in candidates:
            if os.path.exists(c):
                target_path = c
                break
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail=f"PDF file not found: {req.pdf_path}")

    accuser = ForensicAccuser(ledger=ledger, wm_master_seed=WM_SEED)
    try:
        res = accuser.accuse_leaked_document(
            target_path,
            doc_id=req.doc_id,
            total_blocks=req.total_blocks,
            lines_per_block=req.lines_per_block
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic extraction error: {str(e)}")

    # Statistical significance gating:
    # A watermark attribution is only valid if:
    # 1. False accusation probability p < 0.01 (less than 1% chance of error)
    # 2. Correlation match >= 75%
    # 3. Separation margin >= 3 bits (above random baseline noise)
    is_significant = (
        res.false_accusation_probability < 0.01 and
        res.top_candidate.match_percentage >= 75.0 and
        res.separation_margin_bits >= 3
    )

    if not is_significant:
        return {
            "status": "NO_WATERMARK_DETECTED",
            "file_analyzed": target_path,
            "culprit": "NONE (Unmarked / Untracked Document)",
            "verdict": f"INCONCLUSIVE: Correlation {res.top_candidate.match_percentage:.1f}% falls within random noise (p = {res.false_accusation_probability:.2e} > 0.01 threshold). This document was either never encrypted/watermarked via CANARY TRAP or is an untracked original.",
            "sessionEntryHash": res.top_candidate.session_entry_hash,
            "blockHeight": res.top_candidate.block_height,
            "matchScore": f"{res.top_candidate.match_percentage:.1f}% ({res.top_candidate.match_count}/{res.top_candidate.total_blocks}) — Random Baseline Noise",
            "p_value": f"{res.false_accusation_probability:.2e} (Fails p < 0.01 Significance Threshold)",
            "separation_margin": f"{res.separation_margin_bits} bits (Fails >= 3 bits threshold)",
            "leaked_file_hash": res.leaked_file_hash,
            "all_candidates": [
                {
                    "recipient_id": c.recipient_id,
                    "matches": c.match_count,
                    "total_blocks": c.total_blocks,
                    "match_percentage": round(c.match_percentage, 1),
                    "block_height": c.block_height
                }
                for c in res.all_candidate_scores
            ],
            "legalValidity": "Inadmissible: Document shows no cryptographic watermark under Section 63 BSA"
        }

    return {
        "status": "ATTRIBUTED",
        "file_analyzed": target_path,
        "culprit": f"{res.top_candidate.recipient_id}",
        "verdict": f"CONFIRMED: Statistically significant watermark isolated to {res.top_candidate.recipient_id} with separation margin {res.separation_margin_bits} bits.",
        "sessionEntryHash": res.top_candidate.session_entry_hash,
        "blockHeight": res.top_candidate.block_height,
        "matchScore": f"{res.top_candidate.match_percentage:.1f}% ({res.top_candidate.match_count}/{res.top_candidate.total_blocks})",
        "p_value": f"{res.false_accusation_probability:.2e}",
        "separation_margin": f"{res.separation_margin_bits} bits",
        "leaked_file_hash": res.leaked_file_hash,
        "all_candidates": [
            {
                "recipient_id": c.recipient_id,
                "matches": c.match_count,
                "total_blocks": c.total_blocks,
                "match_percentage": round(c.match_percentage, 1),
                "block_height": c.block_height
            }
            for c in res.all_candidate_scores
        ],
        "legalValidity": "Structured under Section 63 Bharatiya Sakshya Adhiniyam, 2023"
    }


# Mount static audit console dist for browser access at http://127.0.0.1:8001/console
console_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "deck", "audit", "dist"))
if os.path.exists(console_dist):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import RedirectResponse
    
    # Redirect root to /console
    @app.get("/")
    def redirect_root_to_console():
        return RedirectResponse(url="/console/")
        
    app.mount("/console", StaticFiles(directory=console_dist, html=True), name="console")
    
    # Also mount /assets directly at root as fallback
    assets_dir = os.path.join(console_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets_fallback")

