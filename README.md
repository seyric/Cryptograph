# CANARY TRAP

> **Every copy is different. Every leak has a name.**

Post-quantum copy-attribution and decryption provenance for multi-recipient
document distribution. Target problem: Smart India Hackathon 2026, **SIH26237**
(Ministry of Defence). Fully offline and air-gapped: no cloud KMS, no public
blockchain, no network access at runtime. NIST post-quantum algorithms
(ML-KEM-768, ML-DSA-65).

---

## The idea

One document is encrypted **once** and handed to many recipients. Each recipient
decrypts a subtly different copy. If a copy leaks, the system must name the
recipient who decrypted it, with cryptographic evidence.

CANARY TRAP does this by never letting an unmarked plaintext exist:

1. **Encrypt once.** The sender splits the document into text blocks, renders
   each block in two variant streams (A/B), and encrypts every variant under its
   own single-use AES-256-GCM key.
2. **Wrap per recipient.** The outer content key `K_out` is wrapped to each
   recipient's ML-KEM-768 public key, so every recipient opens the same
   container with their own capsule.
3. **No log, no key.** A recipient must sign a `DECRYPT_REQUEST` with ML-DSA-65.
   The validator quorum validates identity, policy and quota, commits the request
   to a hash-chained ledger, and only then releases the Shamir shares for the
   variants selected by that session's codeword.
4. **The copy is the evidence.** The codeword is derived from the committed
   ledger entry, so the recovered watermark points back at one specific
   committed decryption session.
5. **Prove it offline.** `tracer/` builds a self-contained evidence bundle and
   `tracer/verify.py` re-checks every signature and Merkle proof with zero
   network access.

---

## Repository layout

```
core/          keys, post-quantum primitives, Shamir sharing, Merkle tree, container build
vault/         hash-chained ledger, Merkle inclusion proofs, entries and checkpoints
mark/          watermark embed and extract (block segmentation, variant streams, codeword)
tracer/        leak analysis, attribution scoring, evidence bundle, offline verifier
gate/          decrypt-request validation, quorum consensus, threshold key release
api/           recipient-facing daemon: local keys, request signing, document assembly
console/       web UIs: console/audit (cluster + forensics), console/viewer (recipient)
cli/           command-line tools
bench/         benchmark suite, end-to-end demo runner, attack harness
docs/          architecture, protocol, threat model, benchmarks, naming, rebrand report
third_party/   third-party material, licence texts, reserved patch area
tests/         full pytest suite
```

Module boundaries and the reasoning behind them: `docs/architecture.md`.

---

## Quickstart (offline)

```powershell
# 1. environment
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. tests  (24 tests, all deterministic, no network)
.venv\Scripts\python.exe -m pytest

# 3. full end-to-end demo: distribute, decrypt, leak, attribute, verify offline,
#    then run the three attack scenarios
.venv\Scripts\python.exe bench\run_demo.py

# 4. benchmark suite + scaling study
.venv\Scripts\python.exe bench\benchmark_suite.py

# 5. distribute a real PDF to N recipients and attribute a leak
.venv\Scripts\python.exe bench\run_custom_distribution.py --pdf my.pdf --num-recipients 10 --leaker 7
```

### Services

```powershell
# validator / quorum node  (one process per node; ports 8001-8004)
.venv\Scripts\python.exe -m uvicorn gate.main:app --host 127.0.0.1 --port 8001

# recipient daemon (holds recipient keys, mounts the viewer)
.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 5001
```

Then: `http://127.0.0.1:8001/console/` for the audit console and
`http://127.0.0.1:5001/` for the recipient portal (both need `npm run build` in
`console/audit` and `console/viewer`).

### Command line

```powershell
.venv\Scripts\python.exe -m cli.sender distribute --pdf doc.pdf --doc-id DOC_001 --recipients ALICE,BOB
.venv\Scripts\python.exe -m tracer.verify EVIDENCE_BUNDLE.json
```

---

## Cryptographic primitives

| Function | Primitive | Standard | Sizes |
|---|---|---|---|
| Key encapsulation | ML-KEM-768 | NIST FIPS 203 | ek 1184 B, ct 1088 B, secret 32 B |
| Digital signatures | ML-DSA-65 | NIST FIPS 204 | vk 1952 B, signature 3309 B |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D | key 32 B, nonce 12 B, tag 16 B |
| Secret sharing | Shamir over `F_p`, `p = 2^256 + 297` | — | `(t=3, n=4)`, 33-byte share values |
| Hashing | SHA3-256 | NIST FIPS 202 | 32 B |
| Merkle log | binary tree, domain separated `0x00` leaf / `0x01` node | RFC 9162 style | `O(log n)` inclusion proof |
| Canonical serialization | key-sorted JSON, no whitespace | RFC 8785 style | — |

`p = 2^256 + 297` is the smallest prime greater than `2^256`, so every 32-byte
AES key maps into the field with no rejection sampling and no wrap-around.

Providers behind `core/pqc.py` are `kyber-py` and `dilithium-py` (MIT OR
Apache-2.0). Both are explicitly educational libraries with no side-channel
hardening — `core/pqc.py` is the single swap point for a hardened provider. See
`THIRD_PARTY.md` §2.1.

---

## Verification

```powershell
.venv\Scripts\python.exe -m pytest          # expect: 24 passed
```

Evidence bundles are verified with zero network access:

```powershell
.venv\Scripts\python.exe -m tracer.verify path\to\EVIDENCE_BUNDLE.json
```

Checks performed, in order: recipient ML-DSA-65 signature (non-repudiation),
recomputed session entry hash, Merkle inclusion proof against the block root,
validator quorum signatures, and the statistical attribution threshold.

---

## Honest status

This is a hackathon prototype, not a production system. The following are known
limitations of the **current implementation** and are documented, not hidden.
They are listed so nobody is surprised under questioning.

1. **The quorum threshold is not enforced.** `gate/consensus.py` collects peer
   votes but a block is still committed when fewer than three signatures are
   gathered (the missing-vote branch is a no-op), so a single reachable node can
   commit. The 4-node cluster and its fault tolerance are real; the enforcement
   of `≥3-of-4` is not yet implemented.
2. **Manifest signatures are stored but not verified.** `gate/main.py` accepts a
   `MANIFEST` without checking the sender's ML-DSA-65 signature, unlike
   `ENROLL` and `DECRYPT_REQUEST`, which are verified.
3. **Quorum certificates are not yet uniformly defined.** The proposer signs a
   candidate header, while the offline verifier checks block signatures against
   the block hash, and treats a signature with no accompanying public key as
   valid. Evidence bundles therefore prove the recipient's non-repudiation
   strongly, and the quorum layer weakly.
4. **Shamir shares are stored in cleartext.** The `key_shares.encrypted_share`
   column holds base64-encoded share bytes, not ciphertext.
5. **Watermark extraction strategy 1 reads the ground truth.** It regex-reads
   `Tw` operators out of the PDF content stream, so it reports full confidence on
   documents that still contain them. Strategy 2 (geometric measurement) is the
   one that survives re-rendering, and it is the weaker of the two.
6. **The viewer relies on the browser's PDF renderer**, not a bundled PDF
   renderer, so the recipient must use a browser with native PDF support.
7. **If a recipient's public key is missing locally, `cli/sender.py` generates a
   throwaway key** so the demo can continue; that recipient then cannot decrypt.
8. **The watermark is typographic.** Robustness to print-and-scan or to document
   re-typesetting is not implemented; error-correcting codes (Reed-Solomon) are
   the planned mitigation.

Remediation order and scope are tracked in `docs/architecture.md` §7.

---

## Licensing and attribution

- CANARY TRAP's own code: see `LICENSE`.
- Every third-party component, version, licence and purpose: `THIRD_PARTY.md`.
- How this tree was derived from the earlier workspace, with file-level evidence:
  `docs/rebrand-report.md`.

