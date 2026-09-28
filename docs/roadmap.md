# Roadmap

Ordered by risk reduction, not by convenience. Each item names the change, why it
matters, and what it would break. Nothing here is started without approval, and
items marked **new dependency** need explicit sign-off first.

---

## P0 — Correctness of the evidence chain

These three make the system's central claim true. Until they are done, the
security properties in `docs/threat-model.md` are aspirational.

### 1. Enforce the quorum threshold
`warden/consensus.py` commits a block even when fewer than three validator
signatures are collected — the missing-quorum branch is a `pass`. Fix: return an
error and commit nothing below threshold; add a test that asserts a block is
*not* committed with one node reachable.
*Breaks:* the single-node demo path, which currently relies on the permissive
branch. Expect to add an explicit `--single-node` development flag.
*Why first:* an administrator controlling one node can currently forge history.

### 2. Verify manifest signatures
`warden/service.py` accepts `MANIFEST` without checking the sender's ML-DSA-65
signature, unlike `ENROLL` and `DECRYPT_REQUEST`. Fix: add
`PolicyEngine.validate_manifest_request` and call it, mirroring the enrolment
path.
*Breaks:* any sender that does not actually sign its manifest — which is every
existing caller, so the demo sender must be fixed in the same change.

### 3. Define the quorum certificate once
Three different notions of "the signed message" exist today. Fix: a single
`chronicle/block_cert.py` defining the canonical block-header bytes, used by the
proposer when signing, by the ledger when sealing, and by `hound/verify.py` when
checking. Also make a validator signature without an accompanying public key a
**rejection**, not a pass.
*Breaks:* previously produced evidence bundles. Version the format
(`canarytrap-evidence-v2`) and keep the old verifier reachable for old bundles.

---

## P1 — Robustness of attribution

### 4. Pixel watermark layer — **new dependency, needs approval**
The demo requirement "a photo of one screen is analysed" cannot be met by the
current typographic channel: a camera photo destroys PDF word-spacing
semantics. This needs a second channel behind `dye/embedder_adapter.py`.
Candidates evaluated in `THIRD_PARTY.md` §6: `blind_watermark` (MIT, whole-page
DWT-DCT-SVD), `invisible-watermark` (MIT, but unmaintained and drags in torch),
StegaStamp (GPU-oriented). Reed-Solomon (`reedsolo`, MIT-0) would be added
alongside to correct the bit errors a photo introduces.
*Explicitly out of scope until approved* — this changes behaviour and adds
dependencies.

### 5. Error-correct the codeword
Wrap the per-session codeword in a Reed-Solomon code so a few mis-recovered bits
do not cost whole blocks. Additive, no format change to the ledger.

### 6. Retire extraction strategy 1
`dye/extractor.py` strategy 1 reads `Tw` operators straight out of the content
stream and reports confidence `1.0`, which flatters the results. Either delete it
or report it as a diagnostic channel that is not evidence-grade.

---

## P2 — Structural debt (from `docs/architecture.md` §6)

### 7. Split `warden/service.py`
Move the FastAPI app construction, the Pydantic models and the forensics
endpoint into separate modules. ~420 lines today.

### 8. Split the two SPAs
`deck/audit/src/App.jsx` (~580 lines) and `deck/viewer/src/App.jsx` (~450 lines)
into per-panel components. Pure front-end, no protocol impact.

### 9. Consistent error types
Add `seal/errors.py` — `CanaryTrapError` and subclasses — and replace the bare
`RuntimeError`/`ValueError` raises in library code. Keep the exception *types*
compatible at the boundary so tests and callers are unaffected.

### 10. Uniform type hints and module docstrings
Docstrings are now in place on the new and split modules; the inherited ones
still carry their original text. Type hints exist but are inconsistent.

---

## P3 — Licensing and provenance

### 11. Decide on the PDF engine — **needs a decision**
PyMuPDF is AGPL-3.0. For a Ministry of Defence submission this is a procurement
question, not just a legal one. Lifting it behind a `pdf_adapter` (one file,
`dye/` only) is the first step either way; swapping to `pypdfium2`
(BSD-3-Clause + Apache-2.0) for rendering and `pdfminer.six` (MIT) for text is
the second, and is a real project rather than a refactor.

### 12. Replace the post-quantum provider — **needs a decision**
`kyber-py` and `dilithium-py` state they are educational and not hardened
against side channels. `seal/pqc_adapter.py` exists precisely so this can be
swapped for a `liboqs`-backed adapter. liboqs is MIT, but has no prebuilt Windows
binary, so every deployment machine would need a CMake/MSVC build.

### 13. Clean-room rewrite of the inherited modules
The code was inherited from an unlicensed SIH26237 project and relocated, not
rewritten — see `THIRD_PARTY.md` §1. A genuine rewrite is a separate, larger
project. Doing it package by package, with the 24 tests re-pinned to the new
behaviour as each one is replaced, is the only way to keep the suite meaningful
during the change.

### 14. Resolve `third_party/unverified/hero.png`
Unused, no metadata, no provenance. Delete it, or establish where it came from.

---

## Explicitly declined

- **Liquid Glass UI restyle.** The Apple HIG material guidance was supplied, but
  adopting it means a new dependency (`liquid-glass-react`) plus a visual
  redesign of `deck/`. Out of scope for a behaviour-preserving restructure;
  raise it as its own piece of work.
- **Hyperledger Fabric or any external ledger.** The hash-chained log with
  signed tree heads in `chronicle/` meets the offline constraint without
  orchestration overhead.
