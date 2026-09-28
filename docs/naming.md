# Naming scheme

The single, consistent naming scheme for CANARY TRAP, and the exact token map
that was applied. Referenced by `docs/rebrand-report.md`.

---

## 1. Product identity

| Layer | Value |
|---|---|
| Display name | `CANARY TRAP` |
| Tagline | *Every copy is different. Every leak has a name.* |
| Python distribution / repo | `canary-trap` |
| npm packages | `canary-trap-console`, `canary-trap-viewer` |
| Container extension | `.ct` |
| Evidence bundle version | `canarytrap-evidence-v1` |
| Container magic string | `canarytrap/v1` |
| Default ledger file | `canarytrap_ledger.db` |
| Runtime data directory | `data/` (per-node subdirectories), `bench_data/` for demo output |
| CSS class prefix | `ct-` |

## 2. Identifier tiers

| Tier | Pattern | Used for |
|---|---|---|
| Environment variables | `CANARY_TRAP_*` | `CANARY_TRAP_NODE_ID`, `CANARY_TRAP_SHARE_INDEX`, `CANARY_TRAP_DB_PATH`, `CANARY_TRAP_WM_SEED`, `CANARY_TRAP_RECIPIENT_ID`, `CANARY_TRAP_VALIDATOR_URL` |
| Short module constants | `CT_*` | `CT_MAGIC`, `CT_HOST_01` |
| Derived constants | `CANARY_TRAP_*` | `CANARY_TRAP_GENESIS_ROOT`, `CANARY_TRAP_DEFENCE_MASTER_SEED_2026`, `CANARY_TRAP_GLOBAL_WATERMARK_SEED_2026`, `CANARY_TRAP_CUSTOM_MASTER_SEED_2026`, `CANARY_TRAP_M420_BENCHMARK_SEED_2026`, `CANARY_TRAP_AUDIT_PAYLOAD_CANONICAL_2026` |
| Paths and filenames | `canarytrap` | ledger file, user-facing paths |
| Display text | `CANARY TRAP` | UI headings, banners, docs |

## 3. Package layout

| Package | Responsibility |
|---|---|
| `seal/` | Post-quantum adapter, Shamir sharing, Merkle tree, container build |
| `warden/` | Decrypt-request validation, quorum consensus, key release, validator API |
| `chronicle/` | Hash-chained ledger: entry hashing, schema, Merkle proofs, chain verification |
| `dye/` | Watermark layers: text layer today (segmentation, variants, codeword, extraction) |
| `hound/` | Leak attribution, evidence bundle, offline verification |
| `bridge/` | Recipient daemon: local keys, request signing, document assembly |
| `deck/` | Web UIs (`deck/audit/`, `deck/viewer/`) |
| `gauntlet/` | Benchmarks, demo runner, fixtures, attack harness |
| `ct/` | Command-line tools |
| `docs/` | Architecture, protocol, threat model, benchmarks, naming, rename map, roadmap, rebrand report |
| `third_party/` | Third-party material, licence texts, patch area |
| `tests/` | Consolidated pytest suite |

Adapter modules - one seam per external library:

| Adapter | Wraps | Replacing it touches |
|---|---|---|
| `seal/pqc_adapter.py` | `kyber-py` / `dilithium-py` | nothing else |
| `bridge/pdf_adapter.py` | PyMuPDF (`fitz`) | `dye/`, `seal/container.py`, `bridge/session.py` |
| `dye/embedder_adapter.py` | the text watermark channel | `hound/`, `bridge/` |
| `chronicle/schema.py` | SQLite DDL | `chronicle/ledger.py` |

Packages are imported as **top-level modules** (`from seal.pqc_adapter import ...`), which
matches the flat layout above. `pytest.ini` puts the repository root on
`sys.path`, so no `PYTHONPATH` juggling is needed.

Filenames that carried no brand token were deliberately **not** renamed
(`pqc.py`, `shamir.py`, `merkle.py`, `ledger.py`, `policy.py`, `key_custody.py`,
`consensus.py`, `segmenter.py`, `extractor.py`, `variant_gen.py`, `codeword.py`,
`accuse.py`, `evidence_bundle.py`, `verify.py`, `client_crypto.py`,
`build_container.py`). Only package directories and brand-bearing filenames

## 4. Token map applied

| Old token | New token | Occurrences |
|---|---|---|
| `SIGIL` (prose, banners, headings) | `CANARY TRAP` | 53 |
| `SIGIL_NATIONAL_DEFENCE_MASTER_SEED_2026` | `CANARY_TRAP_DEFENCE_MASTER_SEED_2026` | 3 |
| `SIGIL_GLOBAL_WATERMARK_SEED_2026` | `CANARY_TRAP_GLOBAL_WATERMARK_SEED_2026` | 1 |
| `SIGIL_CUSTOM_MASTER_WATERMARK_SEED_2026` | `CANARY_TRAP_CUSTOM_MASTER_SEED_2026` | 1 |
| `SIGIL_M420_BENCHMARK_SEED_2026` | `CANARY_TRAP_M420_BENCHMARK_SEED_2026` | 1 |
| `SIGIL_AUDIT_TRANSACTION_PAYLOAD_CANONICAL_2026` | `CANARY_TRAP_AUDIT_PAYLOAD_CANONICAL_2026` | 1 |
| `SIGIL_GENESIS_ROOT` | `CANARY_TRAP_GENESIS_ROOT` | 1 |
| `SIGIL_MAGIC` | `CT_MAGIC` | 1 |
| `SIGIL_v1` | `canarytrap/v1` | 1 |
| `SIGIL_NODE_ID`, `SIGIL_SHARE_INDEX`, `SIGIL_DB_PATH`, `SIGIL_WM_SEED` | `CANARY_TRAP_*` | 2 each |
| `SIGIL_RECIPIENT_ID`, `SIGIL_VALIDATOR_URL` | `CANARY_TRAP_*` | 1 each |
| `SIGIL_HOST_01` | `CT_HOST_01` | 1 |
| `sigil-evidence-v1` | `canarytrap-evidence-v1` | 2 |
| `sigil_ledger.db` | `canarytrap_ledger.db` | 9 |
| `sigil_container_path` | `ct_container_path` | 3 |
| `sigil_test_env` | `ct_test_env` | 1 |
| `sigil-header` | `ct-header` | 2 |
| `.sigil` (extension) | `.ct` | 17 |
| `demo_data` | `bench_data` | 17 |
| `validator_node.ledger` | `vault.ledger` | 12 |
| `validator_node.main` | `warden.service` | 1 |
| `validator_node.policy` | `warden.policy` | 6 |
| `validator_node.key_custody` | `warden.custody` | 7 |
| `validator_node` (residual) | `gate` | 2 |
| `watermark_engine` | `mark` | 19 |
| `forensic_lab` | `tracer` | 9 |
| `offline_verifier` | `tracer` | 4 |
| `recipient_client.daemon` | `api` | 8 |
| `sender_tool.build_container` | `seal.container` | 6 |
| `sender_tool.cli` | `ct.sender` | 1 |
| `from crypto.` | `from core.` | 30 |
| `audit_console` | `console/audit` | 3 |
| `demo/attack_scripts` | `gauntlet/attacks` | 3 |

## 5. Compatibility effects

Renaming a brand also renames identifiers that cross a boundary. Each was applied
consistently on both the producing and consuming side, so behaviour inside this
codebase is unchanged. What changes is compatibility with artefacts produced
under the previous naming.

| Item | Effect of the rename |
|---|---|
| `canarytrap-evidence-v1` | Validated on read by `tracer/verify.py`. Bundles produced before the rebrand are rejected; bundles produced after verify normally. |
| `.ct` extension | Path defaults and `.gitignore` only; no reader validates the extension. |
| `canarytrap/v1` magic string | Written into the container JSON, never validated on read, so old containers still parse. |
| `canarytrap_ledger.db` | A new ledger file is created. No `data/` directory existed at the time of the rebrand, so nothing required migration. |
| `CANARY_TRAP_*` environment variables | Operator-facing: scripts setting the old names must be updated. |
| Watermark master seeds | Key material. Sender and tracer must agree; both sides were renamed together. Documents watermarked before the change are no longer attributable. |
| `CANARY_TRAP_GENESIS_ROOT` | Changes the genesis block hash. No chain existed on disk at the time of the rebrand. |
| `CT_MAGIC` | Was dead code (never referenced) before and after. |
| Documented commands | `warden.service:app`, `bridge.service:app`, `ct.sender`, `hound.verify`, `gauntlet/...`, `tests/...` replace the old paths. |

## 6. Rules for future contributors

1. Never introduce a new brand string. Use the tiers in §2.
2. New packages go under one of the existing top-level directories.
3. New dependencies get pinned **and** recorded in `THIRD_PARTY.md` in the same change.
4. Anything crossing a format boundary carries a docstring note saying so, and its
   rename must be recorded in §5.

