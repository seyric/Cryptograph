# Architecture

How CANARY TRAP is put together, and why the boundaries sit where they do.

## 1. The invariant

One document is encrypted once and handed to many recipients. Each recipient
decrypts a subtly different copy, and a leaked copy must name the recipient who
decrypted it, with cryptographic proof.

The system never produces an unmarked plaintext. Documents are segmented into
text blocks; each block is rendered in two variant streams (A/B) that differ
only in a 0.750 pt word-spacing shift; each variant is encrypted under its own
single-use AES-256-GCM key; and the key set is split with Shamir `(t=3, n=4)`.
A recipient must sign a `DECRYPT_REQUEST` with ML-DSA-65; only after that
request is committed to the ledger does the quorum release the shares for the
variants selected by *that session's* codeword. Because the codeword is derived
from the committed entry hash, the watermark in a leaked copy points back at one
specific committed decryption session.

## 2. Package responsibilities

| Package | Owns | Never does |
|---|---|---|
| `seal/` | post-quantum adapter, Shamir sharing, Merkle tree, container assembly | talks to a database, a browser, or the network |
| `chronicle/` | entry hashing, SQLite schema, block chain, Merkle proofs, integrity scan | policy decisions, key release |
| `warden/` | request validation, quorum consensus, threshold key release, validator HTTP API | cryptography primitives, document parsing |
| `dye/` | watermark channels: segmentation, variant rendering, codeword, extraction | ledger access, policy |
| `hound/` | attribution scoring, evidence bundles, offline verification | key material, document assembly |
| `bridge/` | recipient private keys, request signing, document assembly, daemon HTTP API | quorum logic, ledger writes |
| `deck/` | two React SPAs | any cryptographic operation |
| `gauntlet/` | demo, benchmarks, fixtures, attack scenarios | production code paths |
| `ct/` | command-line entry points | — |

Dependencies flow one way at runtime: `bridge` → `warden` → `chronicle` → `seal`.
`hound` reads from `chronicle` and `dye` but writes to neither. `gauntlet` and
`ct` sit outside and may use anything.

## 3. Data flow

```
sender        seal/container.py  segments, renders A/B, encrypts each variant,
                               Shamir-splits every key, wraps K_out per
                               recipient with ML-KEM-768  ->  .ct container
                               + node share bundle + signed manifest

warden        /api/manifest     commits MANIFEST, stores shares
              /api/enroll       commits ENROLL, stores public keys
              /api/request_decrypt
                               verifies signature + policy + quota,
                               commits DECRYPT_REQUEST, releases the
                               codeword-selected shares to the recipient's
                               ephemeral ML-KEM key

chronicle     commits blocks, hashes entries, serves Merkle proofs

bridge        unwraps its capsule, signs the request, reconstructs the
              variant keys by Lagrange interpolation, decrypts the chosen
              block variants, and assembles the watermarked PDF in memory

hound         dye/embedder_adapter extracts the codeword from the leaked file,
              scores it against every committed session, builds the evidence
              bundle; hound/verify.py re-checks it with no network access
```

## 4. The seams

One adapter per external library, so a provider can be replaced in one place:

| Seam | Wraps | Consumers |
|---|---|---|
| `seal/pqc_adapter.py` | `kyber-py`, `dilithium-py` | everything, via `MLKEM768` / `MLDSA65` |
| `dye/embedder_adapter.py` | the watermark channel | `seal/container.py`, `bridge/session.py`, `hound/attribution.py` |
| `chronicle/schema.py` | SQLite DDL | `chronicle/ledger.py` |
| `chronicle/entry.py` | the entry-hash definition | `chronicle/ledger.py`, `hound/verify.py` |

`chronicle/entry.py` is the most important of these. The entry hash was
originally hand-written in three places — twice in the ledger and once in the
offline verifier. A divergence between the producer and the verifier would
produce bundles that look valid and are not, which is the worst possible failure
for a system whose whole purpose is evidence.

PyMuPDF is currently reached directly from `dye/text_layer.py`,
`dye/assembler.py`, `dye/extractor.py` and the `gauntlet` scripts. Lifting it
behind a `pdf_adapter` is tracked in `docs/roadmap.md` — it is the only route to
dropping the AGPL-licensed engine.

## 5. Cryptographic choices

| Purpose | Choice | Reason |
|---|---|---|
| KEM | ML-KEM-768 (FIPS 203) | NIST category 3; `seal/pqc_adapter.py` is swappable |
| Signatures | ML-DSA-65 (FIPS 204) | same category; used for requests, enrolment, block seals |
| AEAD | AES-256-GCM | single-use key per variant block |
| Sharing | Shamir over `F_p`, `p = 2^256 + 297` | smallest prime above `2^256`, so every 256-bit AES key embeds with no rejection sampling and no wrap-around |
| Hashing | SHA3-256 (FIPS 202) | independent of SHA-2 |
| Merkle | binary, `0x00` leaf / `0x01` node | domain separation; RFC 9162 style inclusion proofs |
| Serialisation | key-sorted, whitespace-free JSON | deterministic, so key order cannot change an entry's identity |

## 6. Known structural debt

Recorded, not hidden — see also the README's "Honest status".

1. `warden/service.py` is ~440 lines: the FastAPI app, its Pydantic models, the
   forensics endpoint and the static mount all live in one module. Splitting the
   forensics endpoint into a router is the obvious next cut.
2. `gauntlet/demo.py` is ~410 lines. It is a linear orchestration script, so
   splitting it further would obscure the sequence of the demo; the fixture text
   has already been moved out to `gauntlet/fixtures.py`.
3. `deck/audit/src/App.jsx` is now ~170 lines after being split into
   `StatusList`, `BlockList` and `ForensicPanel`; `deck/viewer/src/App.jsx` is
   ~250 lines and is still a single file, and would benefit from the same
   treatment.
4. Type hints are present but not uniform. A small error hierarchy
   (`CanaryTrapError`, `PolicyError`, `LedgerError`, `AttributionError`) in
   `seal/errors.py`, replacing the bare `RuntimeError`/`ValueError` raises in
   library code, is specified in `docs/roadmap.md` and only partially
   realised: `bridge/session.py` now raises `ContainerKeyError` for a container
   that will not open, so the daemon can report *why* instead of an empty
   `InvalidTag` message.
5. PyMuPDF is not yet behind an adapter.
6. The inherited modules were relocated and renamed, not rewritten. See
   `THIRD_PARTY.md` §1 and `docs/RENAME_MAP.md`.

