"""Hardening Test 2: Live Multi-Process 4-Node HTTP Cluster & Fault Tolerance Test.

Spawns 4 independent FastAPI Uvicorn servers on ports 8001, 8002, 8003, 8004,
validates live HTTP 2-phase commit consensus, kills Node 4 (f=1 Byzantine fault),
and proves that 3-of-4 quorum consensus survives and commits transactions seamlessly.
"""

import os
import sys
import time
import subprocess
import urllib.request
import urllib.error
import json
import shutil
import pytest

from seal.pqc_adapter import MLDSA65, b64_encode, b64_decode, canonical_json
from bridge.session import RecipientCryptoSession


def wait_for_node(url: str, timeout: float = 12.0) -> bool:
    """Poll node /api/status until ready or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(f"{url}/api/status")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("integrity_healthy") is True:
                        return True
        except Exception:
            time.sleep(0.3)
    return False


def test_live_cluster_4node_bft_and_fault_tolerance(tmp_path):
    cluster_dir = str(tmp_path / "live_cluster_data")
    os.makedirs(cluster_dir, exist_ok=True)

    processes = {}
    node_configs = [
        {"id": "NODE_01", "port": 8001, "share": 1},
        {"id": "NODE_02", "port": 8002, "share": 2},
        {"id": "NODE_03", "port": 8003, "share": 3},
        {"id": "NODE_04", "port": 8004, "share": 4},
    ]

    try:
        # 1. Spawn 4 independent FastAPI Uvicorn processes
        for cfg in node_configs:
            n_id = cfg["id"]
            port = cfg["port"]
            share = cfg["share"]
            db_file = os.path.join(cluster_dir, f"{n_id.lower()}_ledger.db")

            env = os.environ.copy()
            env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            env["CANARY_TRAP_NODE_ID"] = n_id
            env["CANARY_TRAP_SHARE_INDEX"] = str(share)
            env["CANARY_TRAP_DB_PATH"] = db_file
            env["CANARY_TRAP_WM_SEED"] = "LIVE_CLUSTER_TEST_SEED_2026"

            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "warden.service:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning"
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            processes[n_id] = proc

        # 2. Wait for all 4 nodes to become healthy
        for cfg in node_configs:
            url = f"http://127.0.0.1:{cfg['port']}"
            is_ready = wait_for_node(url, timeout=15.0)
            assert is_ready is True, f"Node {cfg['id']} failed to start on {url}"

        # 3. Test Quorum Consensus Commit on Node 1 (All 4 nodes online)
        alice = RecipientCryptoSession(recipient_id="ALICE_LIVE_01", keys_dir=os.path.join(cluster_dir, "alice_keys"))
        enroll_payload, enroll_sig = alice.get_enroll_payload()

        post_data = json.dumps({"payload": enroll_payload, "signature_b64": enroll_sig}).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:8001/api/enroll",
            data=post_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["status"] == "ENROLLED"
            assert res["block_height"] == 1

        # Give 0.5s for commit broadcast to sync to peers
        time.sleep(0.5)

        # Verify that peer Node 2 also has Block 1
        req_peer = urllib.request.Request("http://127.0.0.1:8002/api/status")
        with urllib.request.urlopen(req_peer, timeout=2.0) as resp:
            st2 = json.loads(resp.read().decode("utf-8"))
            assert st2["chain_tip"]["height"] == 1, "Node 02 should have synchronized Block 1"

        # --------------------------------------------------------------------
        # 4. INJECT BYZANTINE FAULT: Terminate Node 4 (f=1 failure)
        # --------------------------------------------------------------------
        p4 = processes["NODE_04"]
        p4.terminate()
        p4.wait()
        del processes["NODE_04"]

        # Confirm Node 4 is dead
        node4_dead = False
        try:
            with urllib.request.urlopen("http://127.0.0.1:8004/api/status", timeout=1.0) as _:
                pass
        except Exception:
            node4_dead = True
        assert node4_dead is True, "Node 04 must be offline"

        # --------------------------------------------------------------------
        # 5. TEST BFT QUORUM SURVIVAL (3 of 4 nodes remaining: 1, 2, 3)
        # --------------------------------------------------------------------
        bob = RecipientCryptoSession(recipient_id="BOB_LIVE_02", keys_dir=os.path.join(cluster_dir, "bob_keys"))
        b_payload, b_sig = bob.get_enroll_payload()

        post_data_b = json.dumps({"payload": b_payload, "signature_b64": b_sig}).encode("utf-8")
        req_b = urllib.request.Request(
            "http://127.0.0.1:8001/api/enroll",
            data=post_data_b,
            headers={"Content-Type": "application/json"}
        )

        # Quorum must still succeed because 3 nodes (Node 1, 2, 3) are sufficient for 3f+1 = 4 BFT!
        with urllib.request.urlopen(req_b, timeout=5.0) as resp:
            assert resp.status == 200
            res_b = json.loads(resp.read().decode("utf-8"))
            assert res_b["status"] == "ENROLLED"
            assert res_b["block_height"] == 2, f"Expected Block 2, got {res_b['block_height']}"

        time.sleep(0.5)

        # Verify Node 3 synchronized Block 2 despite Node 4 being down!
        req_peer3 = urllib.request.Request("http://127.0.0.1:8003/api/status")
        with urllib.request.urlopen(req_peer3, timeout=2.0) as resp:
            st3 = json.loads(resp.read().decode("utf-8"))
            assert st3["chain_tip"]["height"] == 2, "Node 03 should have synchronized Block 2 under 3-node quorum"

    finally:
        # Clean teardown: kill all child processes
        for n_id, proc in processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        test_live_cluster_4node_bft_and_fault_tolerance(pathlib.Path(td))
        print("[+] Hardening Test 2 (Live 4-Node Cluster & BFT Fault Tolerance) PASSED cleanly!")
