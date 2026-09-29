"""CLI Utility for CANARY TRAP Document Senders.

Usage:
  python -m ct.sender distribute --pdf <path> --doc-id <id> --recipients <r1,r2> --node-url <url>
"""

import os
import sys
import json
import argparse
import urllib.error
import urllib.request

from seal.pqc_adapter import MLDSA65, b64_encode, b64_decode
from seal.container import ContainerBuilder


def main():
    parser = argparse.ArgumentParser(description="CANARY TRAP Document Sender CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dist_parser = subparsers.add_parser("distribute", help="Package and distribute an encrypted document")
    dist_parser.add_argument("--pdf", required=True, help="Path to input PDF file")
    dist_parser.add_argument("--doc-id", required=True, help="Unique document identifier")
    dist_parser.add_argument("--recipients", required=True, help="Comma-separated recipient IDs")
    dist_parser.add_argument("--node-url", default="http://127.0.0.1:8001", help="Validator node URL")
    dist_parser.add_argument("--output", default=None, help="Output .ct container path")
    dist_parser.add_argument(
        "--lines-per-block",
        type=int,
        default=1,
        help=(
            "Lines grouped into one variation block (default 1). This fixes the "
            "codeword length, so the attributor must be told the same value. The "
            "default matches hound/attribution.py, warden/service.py and the audit "
            "console, which all assume one line per block: a 24-line directive then "
            "yields 24 blocks and a statistically decisive attribution."
        ),
    )

    args = parser.parse_args()

    if args.command == "distribute":
        # Load or generate sender signing keypair
        sender_keys_dir = "data/sender_keys"
        os.makedirs(sender_keys_dir, exist_ok=True)
        sk_path = os.path.join(sender_keys_dir, "sender_sk.bin")
        vk_path = os.path.join(sender_keys_dir, "sender_vk.bin")

        if os.path.exists(sk_path):
            with open(sk_path, "rb") as f: sender_sk = f.read()
            with open(vk_path, "rb") as f: sender_vk = f.read()
        else:
            sender_vk, sender_sk = MLDSA65.keygen()
            with open(sk_path, "wb") as f: f.write(sender_sk)
            with open(vk_path, "wb") as f: f.write(sender_vk)

        recipients_list = [r.strip() for r in args.recipients.split(",") if r.strip()]
        recipients_map = {}

        # Resolve each recipient's enrolled ML-KEM public key. Order: local cache
        # (the recipient's own machine), then the validator ledger. If neither
        # has one we must stop: a throwaway key would encrypt a copy nobody can
        # ever open, and silently continue as if distribution had succeeded.
        missing: list[str] = []
        print(f"[*] Resolving enrolled public keys for recipients: {recipients_list}")
        for r_id in recipients_list:
            client_pk_file = f"data/client_keys/{r_id}_kem_pk.bin"
            if os.path.exists(client_pk_file):
                with open(client_pk_file, "rb") as f:
                    recipients_map[r_id] = f.read()
                continue

            try:
                with urllib.request.urlopen(f"{args.node_url}/api/identity/{r_id}", timeout=5) as resp:
                    identity = json.loads(resp.read().decode("utf-8"))
                recipients_map[r_id] = b64_decode(identity["ml_kem_public_key"])
                print(f"    {r_id}: fetched enrolled ML-KEM key from {args.node_url}")
            except urllib.error.HTTPError as err:
                reason = err.read().decode("utf-8", "replace")
                missing.append(f"{r_id} (ledger: {reason})")
            except Exception as err:
                missing.append(f"{r_id} ({err})")

        if missing:
            print("[!] Cannot resolve an enrolled ML-KEM public key for:", file=sys.stderr)
            for item in missing:
                print(f"    - {item}", file=sys.stderr)
            print(
                "[!] Refusing to invent a key: the recipient would be unable to "
                "decrypt this container, and the distribution would look "
                "successful while being broken.\n"
                "    Recipients must enroll first (POST /api/enroll), or the "
                "recipient's own data/client_keys/<id>_kem_pk.bin must be present.",
                file=sys.stderr,
            )
            sys.exit(2)

        print(f"[*] Segmenting document and encrypting variants for '{args.doc_id}'...")
        container_bytes, signed_manifest, node_shares = ContainerBuilder.build_container(
            pdf_path=args.pdf,
            doc_id=args.doc_id,
            recipients_map=recipients_map,
            sender_sk=sender_sk,
            lines_per_block=args.lines_per_block
        )

        out_path = args.output or f"{args.doc_id}.ct"
        with open(out_path, "wb") as f:
            f.write(container_bytes)
        print(f"[+] Container exported: {out_path} ({len(container_bytes)} bytes)")

        # Submit MANIFEST to validator node
        print(f"[*] Submitting MANIFEST to validator ledger at {args.node_url}...")
        manifest_req = urllib.request.Request(
            f"{args.node_url}/api/manifest",
            data=json.dumps(signed_manifest).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(manifest_req) as resp:
            man_res = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Manifest committed on ledger! Block Height: {man_res['block_height']}, Entry: {man_res['entry_hash'][:16]}...")

        # Deposit key shares for Node 1 (in single node mode, or distribute across nodes)
        print(f"[*] Depositing Shamir key shares with validator node at {args.node_url}...")
        shares_payload = {
            "doc_id": args.doc_id,
            "shares": node_shares[1]
        }
        shares_req = urllib.request.Request(
            f"{args.node_url}/api/key_shares",
            data=json.dumps(shares_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(shares_req) as resp:
            sh_res = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Key shares deposited in quorum custody: {sh_res['total_shares_stored']} shares stored.")

        # Also store shares into sibling node databases if present on disk.
        # Each node wraps with its own key, so the sibling's KeyCustodyManager
        # must be used rather than writing plaintext shares directly.
        for idx in range(2, 5):
            p_db = f"data/node_0{idx}/canarytrap_ledger.db"
            if os.path.exists(p_db) and idx in node_shares:
                try:
                    from chronicle.ledger import Ledger
                    from warden.custody import KeyCustodyManager
                    p_ledger = Ledger(p_db, node_id=f"NODE_0{idx}")
                    p_custody = KeyCustodyManager(
                        ledger=p_ledger,
                        node_id=f"NODE_0{idx}",
                        node_share_index=idx,
                        wm_master_seed=b"CANARY_TRAP_DEFENCE_MASTER_SEED_2026",
                    )
                    p_custody.store_shares(args.doc_id, node_shares[idx])
                except Exception:
                    pass

        print(f"\n[SUCCESS] Document '{args.doc_id}' distributed under two-lock broadcast model!")


if __name__ == "__main__":
    main()
