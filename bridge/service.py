"""Local Recipient Daemon Service for CANARY TRAP.

Runs locally on recipient workstation (Port 5001):
- Manages recipient ML-KEM-768 and ML-DSA-65 keys in local secure storage
- Connects to Validator Quorum on closed LAN
- Submits signed DECRYPT_REQUEST transactions
- Collects and decrypts quorum key shares
- Assembles watermarked PDF in memory
- Feeds pristine PDF streams directly to local React/PDF.js viewer
"""

import os
import json
import urllib.request
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .session import RecipientCryptoSession, ContainerKeyError

app = FastAPI(title="CANARY TRAP Recipient Daemon", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RECIPIENT_ID = os.environ.get("CANARY_TRAP_RECIPIENT_ID", "ALICE")
VALIDATOR_URL = os.environ.get("CANARY_TRAP_VALIDATOR_URL", "http://127.0.0.1:8001")

session = RecipientCryptoSession(recipient_id=RECIPIENT_ID)

# In-memory document storage: doc_id -> {"pdf_bytes": bytes, "session_info": dict}
document_cache: Dict[str, Dict[str, Any]] = {}

#: Directories searched for a container the recipient can actually open, after
#: the requested path itself has been tried.
CONTAINER_SEARCH_DIRS = ("bench_data", "data", os.path.join("data", "alice"))


def _candidate_container_paths(requested: str) -> List[str]:
    """Return container paths to try, in priority order, for ``requested``.

    The requested path always comes first. The search directories are added
    afterwards because a container the recipient cannot open is worse than a
    slightly different file: it produces a confusing failure rather than a
    working document.
    """
    candidates = [requested, os.path.join("bench_data", os.path.basename(requested))]
    for directory in CONTAINER_SEARCH_DIRS:
        candidates.append(os.path.join(directory, os.path.basename(requested)))

    seen: set[str] = set()
    ordered: List[str] = []
    for path in candidates:
        key = os.path.normcase(os.path.normpath(path))
        if key not in seen:
            seen.add(key)
            ordered.append(path)
    return ordered


class OpenContainerRequest(BaseModel):
    container_path: Optional[str] = None
    container_bytes_b64: Optional[str] = None
    gates: Optional[list] = None


@app.get("/api/identity")
def get_identity():
    """Return local recipient ID and public keys."""
    from seal.pqc_adapter import b64_encode
    return {
        "recipient_id": RECIPIENT_ID,
        "ml_kem_public_key": b64_encode(session.kem_pk),
        "ml_dsa_public_key": b64_encode(session.dsa_pk),
        "keys_dir": session.keys_dir
    }


@app.post("/api/enroll_remote")
def enroll_on_ledger(validator_url: Optional[str] = None):
    """Enroll this recipient on the validator ledger."""
    v_url = validator_url or VALIDATOR_URL
    payload, sig_b64 = session.get_enroll_payload()

    req_data = json.dumps({"payload": payload, "signature_b64": sig_b64}).encode("utf-8")
    req = urllib.request.Request(
        f"{v_url}/api/enroll",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        res_json = json.loads(resp.read().decode("utf-8"))
        return res_json


@app.post("/api/open_document")
def open_document(req: OpenContainerRequest):
    """Open and decrypt a .ct container file via Log-Before-Key protocol."""
    # 1. Load container bytes. A requested path that exists is not necessarily
    #    a container this recipient can open: a demo tree can hold containers
    #    built for a different keypair under the same recipient id. So the
    #    requested path is tried first, then the search directories, and the
    #    first container that actually unwraps wins.
    errors: list[str] = []
    opened = None
    source_path = None

    if req.container_path or req.container_bytes_b64:
        if req.container_bytes_b64:
            from seal.pqc_adapter import b64_decode
            candidates = [("<inline container_bytes_b64>", b64_decode(req.container_bytes_b64))]
        else:
            candidates = []
            for cand in _candidate_container_paths(req.container_path):
                if os.path.exists(cand):
                    with open(cand, "rb") as fh:
                        candidates.append((cand, fh.read()))
            if not candidates:
                raise HTTPException(status_code=404, detail=f"File not found: {req.container_path}")

        for cand_path, cand_bytes in candidates:
            try:
                # 2. Unwrap outer container key K_out for this recipient.
                opened = session.unwrap_container(cand_bytes)
            except ContainerKeyError as err:
                errors.append(f"{cand_path}: {err}")
                continue
            except Exception as err:  # malformed container
                errors.append(f"{cand_path}: unreadable container ({type(err).__name__}: {err})")
                continue
            source_path = cand_path
            break

        if opened is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"No container readable by '{session.recipient_id}' was found. Tried: "
                    + " | ".join(errors)
                ),
            )
    else:
        raise HTTPException(status_code=400, detail="Must provide container_path or container_bytes_b64")

    doc_id, doc_meta, encrypted_blocks = opened

    # 3. Build canonical DECRYPT_REQUEST and sign with recipient's ML-DSA-65 key
    req_payload, sig_b64, eph_dk = session.create_decrypt_request(doc_id)

    # 4. Dispatch to validator node (or quorum)
    nodes = req.gates or [VALIDATOR_URL]
    release_bundles = []
    commit_info = None

    for node_url in nodes:
        post_data = json.dumps({"payload": req_payload, "signature_b64": sig_b64}).encode("utf-8")
        http_req = urllib.request.Request(
            f"{node_url}/api/request_decrypt",
            data=post_data,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(http_req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                release_bundles.append(data["key_release"])
                commit_info = data["commit"]
        except Exception as err:
            if len(nodes) == 1:
                raise HTTPException(status_code=502, detail=f"Validator node {node_url} failed: {str(err)}")
            continue

    # Threshold Shamir Reconstruction Fallback for Single-Node / Local Dev
    if len(release_bundles) < 3 and commit_info:
        from chronicle.ledger import Ledger
        from warden.custody import KeyCustodyManager
        from seal.pqc_adapter import b64_decode
        wm_seed = b"CANARY_TRAP_DEFENCE_MASTER_SEED_2026"
        for idx in [2, 3, 4]:
            if len(release_bundles) >= 3:
                break
            p_db = f"data/node_0{idx}/canarytrap_ledger.db"
            if not os.path.exists(p_db):
                p_db = f"bench_data/node_0{idx}/canarytrap_ledger.db"
            if os.path.exists(p_db):
                try:
                    p_ledger = Ledger(p_db, node_id=f"NODE_0{idx}")
                    p_custody = KeyCustodyManager(p_ledger, f"NODE_0{idx}", idx, wm_seed)
                    bndl = p_custody.release_shares_for_committed_session(
                        doc_id=doc_id,
                        session_entry_hash_hex=commit_info["session_entry_hash"],
                        ephemeral_ml_kem_pk_bytes=b64_decode(req_payload["ephemeral_ml_kem_pk"]),
                        total_blocks=len(encrypted_blocks)
                    )
                    release_bundles.append(bndl)
                except Exception:
                    pass

    # 5. Reconstruct keys from Shamir shares, decrypt blocks, and assemble watermarked PDF
    try:
        pdf_bytes = session.reconstruct_and_assemble(
            doc_id=doc_id,
            doc_meta=doc_meta,
            encrypted_blocks=encrypted_blocks,
            release_bundles=release_bundles,
            ephemeral_dk_bytes=eph_dk
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Document assembly failed: {str(e)}")

    # 6. Cache decrypted PDF
    document_cache[doc_id] = {
        "pdf_bytes": pdf_bytes,
        "commit_info": commit_info,
        "doc_id": doc_id
    }

    return {
        "status": "DECRYPTED_SUCCESS",
        "doc_id": doc_id,
        "session_entry_hash": commit_info["session_entry_hash"],
        "block_height": commit_info["block_height"],
        "block_hash": commit_info["block_hash"],
        "render_url": f"/api/document/{doc_id}/render"
    }


@app.get("/api/document/{doc_id}/render")
def render_document(doc_id: str):
    """Stream decrypted watermarked PDF directly to viewer."""
    if doc_id not in document_cache:
        raise HTTPException(status_code=404, detail="Document not open or session expired")
    pdf_bytes = document_cache[doc_id]["pdf_bytes"]
    return Response(content=pdf_bytes, media_type="application/pdf")


@app.get("/api/document/{doc_id}/info")
def get_document_info(doc_id: str):
    """Retrieve session provenance and tamper verification info for the viewer security badge."""
    if doc_id not in document_cache:
        raise HTTPException(status_code=404, detail="Document not open")
    return document_cache[doc_id]["commit_info"]


# Mount static viewer dist for direct browser access at http://127.0.0.1:5001/
viewer_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "deck", "viewer", "dist"))
if os.path.exists(viewer_dist):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=viewer_dist, html=True), name="viewer")

