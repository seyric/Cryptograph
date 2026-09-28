# RENAME_MAP.md — every old name, and what it became

Complete record of the `seal` / `warden` / `chronicle` / `dye` / `hound` /
`bridge` / `deck` / `gauntlet` / `ct` restructure. Searching the repository for
any name in the "Old" column below returns hits **only in this file** (and in
`THIRD_PARTY.md` §1, which deliberately names the inherited project).

Two renames are recorded here: the package restructure, and the earlier brand
rename for completeness.

---

## 1. Package directories

| Old | New | Purpose after rename |
|---|---|---|
| `core/` | `seal/` | encryption, key wrapping, key management |
| `gate/` | `warden/` | signed requests, policy, key release |
| `vault/` | `chronicle/` | hash-chained ledger, Merkle proofs |
| `mark/` | `dye/` | watermark layers (text today) |
| `tracer/` | `hound/` | attribution, exoneration, evidence bundles |
| `api/` | `bridge/` | recipient-facing FastAPI service |
| `bench/` | `gauntlet/` | attack harness and benchmarks |
| `cli/` | `ct/` | command-line tools |
| `console/audit/` | `deck/audit/` | audit console SPA |
| `console/viewer/` | `deck/viewer/` | recipient viewer SPA |

## 2. Module files

| Old | New |
|---|---|
| `core/pqc.py` | `seal/pqc_adapter.py` |
| `core/shamir.py` | `seal/sharing.py` |
| `core/merkle.py` | `seal/merkle.py` |
| `core/build_container.py` | `seal/container.py` |
| `gate/main.py` | `warden/service.py` |
| `gate/key_custody.py` | `warden/custody.py` |
| `gate/policy.py` | `warden/policy.py` |
| `gate/consensus.py` | `warden/consensus.py` |
| `vault/ledger.py` | `chronicle/ledger.py` |
| `mark/segmenter.py` | `dye/text_layer.py` |
| `mark/variant_gen.py` | `dye/assembler.py` |
| `mark/extractor.py` | `dye/extractor.py` |
| `mark/codeword.py` | `dye/codeword.py` |
| `tracer/accuse.py` | `hound/attribution.py` |
| `tracer/evidence_bundle.py` | `hound/evidence.py` |
| `tracer/verify.py` | `hound/verify.py` |
| `api/main.py` | `bridge/service.py` |
| `api/client_crypto.py` | `bridge/session.py` |
| `bench/run_demo.py` | `gauntlet/demo.py` |
| `bench/benchmark_suite.py` | `gauntlet/benchmarks.py` |
| `bench/run_custom_distribution.py` | `gauntlet/distribution.py` |
| `bench/attack_scripts/` | `gauntlet/attacks/` |
| `cli/sender.py` | `ct/sender.py` |
| `crypto/tests/`, `watermark_engine/tests/`, `forensic_lab/tests/`, `demo/test_*.py` | `tests/` (single directory) |

## 3. New modules (created, no old equivalent)

| New | Extracted from | Why |
|---|---|---|
| `chronicle/entry.py` | `chronicle/ledger.py`, `hound/verify.py` | the entry-hash definition was hand-written in three places; now one function |
| `chronicle/schema.py` | `chronicle/ledger.py` | SQL DDL, 53 lines out of the ledger class |
| `chronicle/proofs.py` | `chronicle/ledger.py` | `build_inclusion_proof`, `compute_block_hash`, `verify_chain` as pure functions |
| `dye/embedder_adapter.py` | `dye/text_layer.py`, `dye/assembler.py`, `dye/extractor.py` | the watermark-channel seam; `seal/container.py`, `bridge/session.py` and `hound/attribution.py` now call it |
| `gauntlet/fixtures.py` | `gauntlet/demo.py` | demo document text and PDF rendering |
| `pytest.ini` | — | `testpaths` + `pythonpath` so the suite runs without `PYTHONPATH` juggling |

## 4. Module-path references (imports)

| Old import path | New import path |
|---|---|
| `core.pqc` | `seal.pqc_adapter` |
| `core.shamir` | `seal.sharing` |
| `core.merkle` | `seal.merkle` |
| `core.build_container` | `seal.container` |
| `gate.main` | `warden.service` |
| `gate.policy` | `warden.policy` |
| `gate.key_custody` | `warden.custody` |
| `gate.consensus` | `warden.consensus` |
| `gate.ledger` | `chronicle.ledger` |
| `vault.ledger` | `chronicle.ledger` |
| `mark.segmenter` | `dye.text_layer` |
| `mark.variant_gen` | `dye.assembler` |
| `mark.extractor` | `dye.extractor` |
| `mark.codeword` | `dye.codeword` |
| `tracer.accuse` | `hound.attribution` |
| `tracer.evidence_bundle` | `hound.evidence` |
| `tracer.verify` | `hound.verify` |
| `api.client_crypto` | `bridge.session` |
| `api.main` | `bridge.service` |
| `cli.sender` | `ct.sender` |
| `.segmenter` (intra-package) | `.text_layer` |
| `.accuse` (intra-package) | `.attribution` |
| `.key_custody` (intra-package) | `.custody` |
| `.client_crypto` (intra-package) | `.session` |

## 5. Commands, mounts and paths

| Old | New |
|---|---|
| `uvicorn gate.main:app` | `uvicorn warden.service:app` |
| `uvicorn api.main:app` | `uvicorn bridge.service:app` |
| `python -m tracer.verify` | `python -m hound.verify` |
| `python -m cli.sender` | `python -m ct.sender` |
| `python bench/run_demo.py` | `python gauntlet/demo.py` |
| `python bench/benchmark_suite.py` | `python gauntlet/benchmarks.py` |
| `python bench/run_custom_distribution.py` | `python gauntlet/distribution.py` |
| `python bench/attack_scripts/*.py` | `python gauntlet/attacks/*.py` |
| `.\bench\run_demo.ps1` | `.\gauntlet\run_demo.ps1` |
| `../console/audit/dist` | `../deck/audit/dist` |
| `../console/viewer/dist` | `../deck/viewer/dist` |

## 6. Deliberately NOT renamed

These are the wire contract. Renaming them would break the SPAs, any external
script, and previously produced artefacts, so they are byte-identical to before:

| Item | Value | Why unchanged |
|---|---|---|
| HTTP routes | `/api/status`, `/api/enroll`, `/api/manifest`, `/api/request_decrypt`, `/api/forensics/attribute`, … | URLs are the contract; the SPAs `fetch()` them by literal string |
| Console mount path | `/console` | served URL, referenced by the root redirect and the audit SPA |
| Ledger filename | `canarytrap_ledger.db` | on-disk state location |
| Container extension | `.ct` | already renamed in the previous pass; path/format only |
| Evidence version string | `canarytrap-evidence-v1` | validated on read; producer and consumer renamed together |
| Watermark seeds | `CANARY_TRAP_*_SEED_2026` | key material; sender and tracer renamed together |
| Genesis root | `CANARY_TRAP_GENESIS_ROOT` | changes the genesis block hash; no chain existed on disk |
| Environment variables | `CANARY_TRAP_NODE_ID`, `CANARY_TRAP_SHARE_INDEX`, `CANARY_TRAP_DB_PATH`, `CANARY_TRAP_WM_SEED`, `CANARY_TRAP_RECIPIENT_ID`, `CANARY_TRAP_VALIDATOR_URL` | operator contract |
| Class and function names | `Ledger`, `PolicyEngine`, `MLKEM768`, `MerkleTree`, `ForensicAccuser`, … | renaming these would be cosmetic churn; the public API is pinned by the tests |

## 7. Earlier brand rename (for reference)

| Old brand token | New |
|---|---|
| `SIGIL` / `Sigil` / `sigil` (154 occurrences, 38 files) | `CANARY TRAP` / `Canary Trap` / `canarytrap` |
| `crypto/` (first pass) | `core/` (second pass) → `seal/` (this restructure) |
| `watermark_engine/` | `mark/` → `dye/` |
| `validator_node/` | `gate/` → `warden/` |
| `demo/` | `bench/` → `gauntlet/` |
| `audit_console/`, `recipient_client/viewer/` | `console/` → `deck/` |
| `.sigil` | `.ct` |
| `sigil-evidence-v1` | `canarytrap-evidence-v1` |
| `sigil_ledger.db` | `canarytrap_ledger.db` |
| `demo_data/` | `bench_data/` |
| `sigil-header` (CSS) | `ct-header` |
| `SIGIL_*` env vars | `CANARY_TRAP_*` |

