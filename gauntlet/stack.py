"""Live demo stack control: launch, inspect, stop and bootstrap CANARY TRAP.

Three things this script exists to fix:

1. **Services must outlive the shell that started them.** Launching uvicorn with
   redirected stdio from a short-lived shell kills it as soon as that shell
   exits, because the redirected pipe closes. Everything here is spawned
   detached with its own log file.
2. **The demo has to be reproducible.** ``bootstrap`` writes the fixture, enrols
   both identities, and distributes the directive, so a reviewer can go from an
   empty tree to a working browser demo with two commands.
3. **Key material must match.** The container the recipient daemon opens has to
   be built for that daemon's own ML-KEM key. ``bootstrap`` always distributes
   through ``ct/sender``, which resolves the recipient key from the daemon's key
   directory instead of inventing one.

Usage:
    python gauntlet/stack.py up
    python gauntlet/stack.py status
    python gauntlet/stack.py bootstrap
    python gauntlet/stack.py down
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(ROOT, "data", "stack_state.json")
LOG_DIR = os.path.join(ROOT, "data", "logs")
WM_SEED = "CANARY_TRAP_DEFENCE_MASTER_SEED_2026"
DEMO_DOC_ID = "DEFENCE_DIRECTIVE_2026"
DEMO_CONTAINER = os.path.join("bench_data", f"{DEMO_DOC_ID}.ct")
DEMO_SOURCE_PDF = os.path.join("bench_data", "source_directive.pdf")
LEAK_PDF = os.path.join("bench_data", "alice_decrypted.pdf")

#: warden.consensus.STATIC_PEERS is a static topology, so these ports are fixed.
NODES = [
    {"name": "NODE_01", "port": 8001, "share": 1},
    {"name": "NODE_02", "port": 8002, "share": 2},
    {"name": "NODE_03", "port": 8003, "share": 3},
    {"name": "NODE_04", "port": 8004, "share": 4},
]

UI_SERVICES = [
    {"name": "VIEWER", "port": 5173, "dir": os.path.join("deck", "viewer")},
    {"name": "AUDIT", "port": 5174, "dir": os.path.join("deck", "audit")},
]

BRIDGE = {"name": "BRIDGE", "port": 5001}


# ============================================================================
# Process helpers
# ============================================================================

def port_is_open(port: int, host: str = "127.0.0.1") -> bool:
    """True when something is accepting TCP connections on ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex((host, port)) == 0


def get_json(url: str, timeout: float = 5.0):
    """GET ``url`` and decode the JSON body."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def spawn_detached(name: str, argv: list, env: dict, cwd: str = ROOT) -> int:
    """Start ``argv`` detached with output going to ``data/logs/<name>.log``.

    Returns the new process id. ``DETACHED_PROCESS`` plus a file-backed log is
    what keeps the service alive after this script's shell exits.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{name.lower()}.log")
    creationflags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | NEW_PROCESS_GROUP
    with open(log_path, "ab") as log_file:
        log_file.write(f"\n=== {name} started {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n".encode("utf-8"))
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            close_fds=True,
        )
    return proc.pid


def wait_for_port(port: int, timeout: float = 30.0) -> bool:
    """Poll ``port`` until it accepts connections or ``timeout`` elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_is_open(port):
            return True
        time.sleep(0.4)
    return False


def python_env(**extra) -> dict:
    """Environment for a Python service, rooted at the repository."""
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT
    env.pop("CANARY_TRAP_NODE_ID", None)
    env.pop("CANARY_TRAP_SHARE_INDEX", None)
    env.update(extra)
    return env


def load_state() -> dict:
    if not os.path.exists(STATE_PATH):
        return {"services": {}}
    with open(STATE_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)



# ============================================================================
# Commands
# ============================================================================

def cmd_up(args) -> int:
    """Start the four validators, the recipient daemon, and both web UIs."""
    if not args.skip_ui and not os.path.isdir(os.path.join(ROOT, "deck", "viewer", "node_modules")):
        print("[!] deck/*/node_modules missing - run 'npm install' in each deck first, "
              "or pass --skip-ui")
        return 2

    state = load_state()
    started = []

    for node in NODES:
        if port_is_open(node["port"]):
            print(f"[=] {node['name']} already listening on {node['port']}")
            continue
        pid = spawn_detached(
            node["name"],
            [sys.executable, "-m", "uvicorn", "warden.service:app",
             "--host", "127.0.0.1", "--port", str(node["port"]), "--log-level", "warning"],
            python_env(
                CANARY_TRAP_NODE_ID=node["name"],
                CANARY_TRAP_SHARE_INDEX=str(node["share"]),
                CANARY_TRAP_WM_SEED=WM_SEED,
            ),
        )
        state["services"][node["name"]] = {"pid": pid, "port": node["port"]}
        started.append((node["name"], pid, node["port"]))

    if not port_is_open(BRIDGE["port"]):
        pid = spawn_detached(
            BRIDGE["name"],
            [sys.executable, "-m", "uvicorn", "bridge.service:app",
             "--host", "127.0.0.1", "--port", str(BRIDGE["port"]), "--log-level", "warning"],
            python_env(CANARY_TRAP_RECIPIENT_ID="ALICE"),
        )
        state["services"][BRIDGE["name"]] = {"pid": pid, "port": BRIDGE["port"]}
        started.append((BRIDGE["name"], pid, BRIDGE["port"]))

    for ui in UI_SERVICES:
        if args.skip_ui or port_is_open(ui["port"]):
            continue
        pid = spawn_detached(
            ui["name"],
            ["cmd.exe", "/c", f"npm run dev -- --port {ui['port']} --strictPort --host 127.0.0.1"],
            os.environ.copy(),
            cwd=os.path.join(ROOT, ui["dir"]),
        )
        state["services"][ui["name"]] = {"pid": pid, "port": ui["port"], "kind": "ui"}
        started.append((ui["name"], pid, ui["port"]))

    save_state(state)

    for name, pid, port in started:
        ok = wait_for_port(port)
        print(f"[{'ok' if ok else '!!'}] {name} -> port {port} (pid {pid})")
    print("\nstack up. Logs: data/logs/. Next: python gauntlet/stack.py bootstrap")
    return 0


def cmd_down(args) -> int:
    """Stop every service recorded in the stack state, then verify the ports."""
    state = load_state()
    for name, info in list(state.get("services", {}).items()):
        pid = info.get("pid")
        if not pid:
            continue
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"[-] stopped {name} (pid {pid})")
    state["services"] = {}
    save_state(state)

    time.sleep(1.5)
    lingering = [s["port"] for s in NODES + [BRIDGE] + UI_SERVICES if port_is_open(s["port"])]
    if lingering:
        print(f"[!] still listening: {lingering} - these were started outside the stack script")
    else:
        print("[+] all stack ports closed")
    return 0


def cmd_status(args) -> int:
    """Probe every service and print what is actually answering."""
    print("=== validator quorum ===")
    for node in NODES:
        try:
            status = get_json(f"http://127.0.0.1:{node['port']}/api/status")
            print(
                f"  {status['node_id']:<8} port {node['port']}  height {status['block_height']:<3} "
                f"integrity {'OK' if status['integrity_healthy'] else 'FAILED'}  "
                f"tip {status['block_hash'][:16]}..."
            )
        except Exception as err:
            print(f"  {node['name']:<8} port {node['port']}  DOWN ({type(err).__name__})")

    print("=== recipient daemon ===")
    try:
        identity = get_json(f"http://127.0.0.1:{BRIDGE['port']}/api/identity")
        print(f"  {identity['recipient_id']} keys={identity['keys_dir']} bridge=UP")
    except Exception as err:
        print(f"  bridge DOWN ({type(err).__name__})")

    print("=== web UIs ===")
    for ui in UI_SERVICES:
        print(f"  {ui['name']:<8} port {ui['port']}  {'UP' if port_is_open(ui['port']) else 'DOWN'}")

    print("=== demo artifacts ===")
    for path in (DEMO_SOURCE_PDF, DEMO_CONTAINER, LEAK_PDF):
        full = os.path.join(ROOT, path)
        exists = os.path.exists(full)
        size = os.path.getsize(full) if exists else 0
        print(f"  {path:<42} {'present' if exists else 'MISSING'} ({size} bytes)")
    return 0



def _post_json(url: str, payload: dict) -> dict:
    """POST ``payload`` as JSON and decode the JSON response."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=90) as resp:
        return json.loads(resp.read().decode("utf-8"))


def cmd_bootstrap(args) -> int:
    """Enrol the demo identities and distribute the directive to the live cluster."""
    sys.path.insert(0, ROOT)

    from gauntlet.fixtures import write_demo_directive
    from seal.pqc_adapter import MLDSA65, b64_encode
    from bridge.session import RecipientCryptoSession

    if not port_is_open(8001):
        print("[!] validator quorum is not up - run 'python gauntlet/stack.py up' first")
        return 2

    # 1. Deterministic source document: 24 lines at one line per block.
    os.makedirs(os.path.join(ROOT, "bench_data"), exist_ok=True)
    write_demo_directive(os.path.join(ROOT, DEMO_SOURCE_PDF))
    print(f"[+] fixture written: {DEMO_SOURCE_PDF}")

    # 2. The recipient daemon enrols itself with its own ML-DSA-65 signature.
    try:
        res = _post_json("http://127.0.0.1:5001/api/enroll_remote", {})
        print(f"[+] recipient enrolled: {res.get('recipient_id')} block #{res.get('block_height')}")
    except urllib.error.HTTPError as err:
        print(f"[=] recipient enrolment returned HTTP {err.code}: "
              f"{err.read().decode('utf-8', 'replace')[:140]}")

    # 3. The sending office enrols too: an unenrolled sender cannot register a
    #    manifest, because that manifest fixes the authorised recipient list.
    sender_dir = os.path.join(ROOT, "data", "sender_keys")
    os.makedirs(sender_dir, exist_ok=True)
    sender_sk_path = os.path.join(sender_dir, "sender_sk.bin")
    sender_vk_path = os.path.join(sender_dir, "sender_vk.bin")
    sender_kem_pk_path = os.path.join(sender_dir, "sender_kem_pk.bin")

    if not os.path.exists(sender_sk_path):
        sender_vk, sender_sk = MLDSA65.keygen()
        with open(sender_vk_path, "wb") as fh:
            fh.write(sender_vk)
        with open(sender_sk_path, "wb") as fh:
            fh.write(sender_sk)
    if not os.path.exists(sender_kem_pk_path):
        sender_session = RecipientCryptoSession(recipient_id="SENDER_KEM", keys_dir=sender_dir)
        with open(sender_kem_pk_path, "wb") as fh:
            fh.write(sender_session.kem_pk)

    with open(sender_sk_path, "rb") as fh:
        sender_sk = fh.read()
    with open(sender_vk_path, "rb") as fh:
        sender_vk = fh.read()
    with open(sender_kem_pk_path, "rb") as fh:
        sender_kem_pk = fh.read()

    enroll_payload = {
        "type": "ENROLL",
        "recipient_id": "SENDER_OFFICE",
        "ml_kem_public_key": b64_encode(sender_kem_pk),
        "ml_dsa_public_key": b64_encode(sender_vk),
        "timestamp": int(time.time()),
        "device_fingerprint": "DEV_SENDER_OFFICE_01",
    }
    try:
        res = _post_json(
            "http://127.0.0.1:8001/api/enroll",
            {
                "payload": enroll_payload,
                "signature_b64": b64_encode(MLDSA65.sign(sender_sk, enroll_payload)),
            },
        )
        print(f"[+] sender enrolled: {res.get('recipient_id')} block #{res.get('block_height')}")
    except urllib.error.HTTPError as err:
        print(f"[=] sender enrolment returned HTTP {err.code}: "
              f"{err.read().decode('utf-8', 'replace')[:140]}")

    # 4. Distribute. ct/sender resolves the recipient's ML-KEM key from the
    #    daemon's key directory, so the container is guaranteed to be openable.
    argv = [
        sys.executable, "-m", "ct.sender", "distribute",
        "--pdf", DEMO_SOURCE_PDF,
        "--doc-id", DEMO_DOC_ID,
        "--recipients", args.recipients,
        "--node-url", "http://127.0.0.1:8001",
        "--output", DEMO_CONTAINER,
        "--lines-per-block", str(args.lines_per_block),
    ]
    print("[*] distributing directive to", args.recipients, "...")
    result = subprocess.run(argv, cwd=ROOT, env=python_env())
    if result.returncode != 0:
        print("[!] distribution failed")
        return result.returncode

    print("\n[+] bootstrap complete. Open http://localhost:5173 (viewer) and "
          "http://localhost:5174 (audit console), then click 'Decrypt and Open'.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for the stack controller."""
    parser = argparse.ArgumentParser(description="CANARY TRAP live demo stack control")
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up", help="start validators, daemon and UIs detached")
    up.add_argument("--skip-ui", action="store_true", help="do not start the Vite dev servers")
    up.set_defaults(func=cmd_up)

    down = sub.add_parser("down", help="stop everything this script started")
    down.set_defaults(func=cmd_down)

    status = sub.add_parser("status", help="probe every service and list demo artifacts")
    status.set_defaults(func=cmd_status)

    boot = sub.add_parser("bootstrap", help="enrol demo identities and distribute the directive")
    boot.add_argument("--recipients", default="ALICE", help="comma-separated recipient ids")
    boot.add_argument("--lines-per-block", type=int, default=1,
                      help="must match what the attributor assumes (default 1)")
    boot.set_defaults(func=cmd_bootstrap)

    return parser


if __name__ == "__main__":
    parsed = build_parser().parse_args()
    raise SystemExit(parsed.func(parsed))
