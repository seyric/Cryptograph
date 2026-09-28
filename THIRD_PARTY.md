# THIRD_PARTY.md — third-party components in CANARY TRAP

*Every copy is different. Every leak has a name.*

This file is the authoritative index of third-party material in this repository.
It answers four questions for each item: **where it came from**, **which version**,
**under what licence**, and **what we use it for**.

Nothing in this repository requires network access at runtime. All dependencies
are installed once, offline-capable, and pinned in `requirements.txt` (Python) or
`console/*/package.json` (Node).

---

## 1. Provenance of this codebase

Recorded here because it determines what the root `LICENSE` can and cannot cover.

- CANARY TRAP is a **rebrand and restructuring** of an earlier workspace that
  contained, byte-for-byte, the source tree of the public SIH26237 project
  `ChandanMeher4/Sigil` (single author, default branch `chandan`, no `LICENSE`
  file, therefore all rights reserved).
- That earlier tree has been **removed**: its Python modules were moved into the
  new package layout and its documentation was deleted and replaced by the
  documents under `docs/`. The full inventory and file-level evidence is in
  `docs/rebrand-report.md`.
- No licence was ever granted by that upstream project, so **the root `LICENSE`
  applies to CANARY TRAP's own contributions only**. If you intend to publish or
  redistribute this repository, review `docs/rebrand-report.md` section 6 first.
- Third-party *assets* that remain byte-identical in this tree (Vite template
  files, Iconify icons) keep their original licences and are itemised in
  section 4 below. No copyright notice, licence header or attribution belonging
  to any third party has been removed or altered.

---

## 2. Python dependencies (installed, not vendored)

Installed from PyPI into a local virtual environment. Listed in `requirements.txt`.

| Component | Version | Licence | Source | What we use it for |
|---|---|---|---|---|
| **kyber-py** | 1.2.0 | MIT OR Apache-2.0 (dual) | https://github.com/GiacomoPope/kyber-py | ML-KEM-768 key encapsulation (NIST FIPS 203) behind `core/pqc.py` |
| **dilithium-py** | 1.4.0 | MIT OR Apache-2.0 (dual) | https://github.com/GiacomoPope/dilithium-py | ML-DSA-65 signatures (NIST FIPS 204) behind `core/pqc.py` |
| **cryptography** | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography | AES-256-GCM (`AESGCM`) for container, block and share encryption |
| **PyMuPDF** (`fitz`) | 1.28.2 | **AGPL-3.0** or commercial (Artifex Software) | https://github.com/pymupdf/PyMuPDF | Text extraction with font metrics, content-stream rewriting, watermarked PDF assembly |
| **fastapi** | 0.141.1 | MIT | https://github.com/fastapi/fastapi | `gate` validator service and `api` recipient daemon HTTP interfaces |
| **uvicorn** | 0.54.0 | BSD-3-Clause | https://github.com/encode/uvicorn | ASGI server for both services |
| **pydantic** | 2.13.5 | MIT | https://github.com/pydantic/pydantic | Wire-format request models |
| **pytest** | 9.1.1 | MIT | https://github.com/pytest-dev/pytest | Test suite in `tests/` |

Transitive dependencies pulled in by the above (starlette, anyio, h11, idna,
click, colorama, typing-extensions, annotated-types, pydantic-core,
typing-inspection, cffi, pycparser, Pygments, iniconfig, pluggy, packaging) are
all MIT / BSD / Apache-2.0; none are copyleft. Run
`.venv\Scripts\python.exe -m pip freeze > requirements.lock.txt` to capture the
exact resolved set.

### 2.1 Flags raised (read before redistributing)

1. **PyMuPDF is AGPL-3.0.** Imported by `mark/segmenter.py`,
  `mark/variant_gen.py`, `mark/extractor.py`, `tracer/*`, `bench/*` and
  `tests/test_pdf_survival.py`. AGPL-3.0 obligations are only triggered when you
  distribute the software or expose it as a network service. Even so: the AGPL
  text must accompany any redistributed copy, and the source of any modifications
  to PyMuPDF itself must be offered. Permissively-licensed alternatives that
  would need code changes: `pypdfium2` (BSD-3-Clause + Apache-2.0, bundles
  PDFium) for rendering, `pdfminer.six` (MIT) for text extraction.
2. **kyber-py / dilithium-py are self-described as educational.** Both READMEs
  state they are *"not designed to be secure against any form of side-channel
  attack"* and should not be used for real cryptographic applications. They are
  wrapped behind the single interface in `core/pqc.py` precisely so they can be
  swapped for a hardened provider (e.g. a liboqs-backed adapter) without touching
  the rest of the system.

---

## 3. Node / front-end dependencies

Declared in `console/audit/package.json` and `console/viewer/package.json`, and
resolved with exact versions in the adjacent `package-lock.json` files.

| Component | Declared range | Resolved | Licence | What we use it for |
|---|---|---|---|---|
| react | ^19.2.8 | 19.2.8 | MIT | Both single-page apps |
| react-dom | ^19.2.8 | 19.2.8 | MIT | DOM renderer |
| vite | ^8.3.0 | 8.3.0 | MIT | Dev server / bundler |
| @vitejs/plugin-react | ^6.1.1 | 6.1.1 | MIT | React fast-refresh + JSX transform |
| oxlint | ^1.81.0 | 1.81.0 | MIT | Linter (declared in the template; not run in CI here) |
| @types/react, @types/react-dom | ^19.2.x | — | MIT | Editor/type support only |

The apps have no runtime network dependency and no CDN references: fonts are
system fonts, and the document is rendered by the browser's own PDF viewer via an
`<iframe>` pointing at the local daemon.

---

## 4. Third-party files kept verbatim in this tree

These are byte-identical third-party files that we did **not** author. They are
retained (moved out of the application tree where they were unused) and their
licences ship alongside them.

| Path | Source | Licence | Notes |
|---|---|---|---|
| `third_party/licenses/vite-MIT.txt` | `vitejs/vite` (LICENSE) | MIT | Verbatim licence text, fetched from upstream |
| `third_party/template-assets/*` | `vitejs/vite` → `packages/create-vite/template-react` | MIT | `vite.svg`, `react.svg`, `icons.svg`, original `favicon.svg` — unused template art, moved out of both apps |
| `third_party/template-assets/react.svg` | Iconify `logos` icon set, author Gil Barbara | **CC0 1.0** (no attribution required) | Brand logo, template art only |
| `console/audit/.gitignore`, `console/viewer/.gitignore` | Vite template (`_gitignore`) | MIT | Kept in place, unmodified |
| `console/audit/.oxlintrc.json`, `console/viewer/.oxlintrc.json` | Vite template (`_oxlintrc.json`) | MIT | Kept in place, unmodified |
| `console/audit/README.md`, `console/viewer/README.md` | — | — | Rewritten by us; the Vite template READMEs they replace are summarised in `third_party/README.md` |

### 4.1 Unverified asset (do not redistribute until checked)

| Path | Finding |
|---|---|
| `third_party/unverified/hero.png` | 343×361 indexed PNG with no `tEXt`/`iTXt`/`zTXt` metadata, therefore **no provenance**. It was referenced by nothing in the earlier tree, so it was moved out of the apps rather than deleted. Excluded from CANARY TRAP's own `LICENSE` claim. If its origin cannot be established, delete it before publishing. |

### 4.2 Assets authored for CANARY TRAP

| Path | Notes |
|---|---|
| `console/audit/public/favicon.svg` | CANARY TRAP mark, drawn for this project — replaces the Vite logo that the template shipped as the app icon |
| `console/viewer/public/favicon.svg` | Same mark |

---

## 5. Attribution and notice obligations — summary

| Obligation | Applies to | Where satisfied |
|---|---|---|
| Retain MIT licence text | Vite template files, React, Vite, oxlint and other MIT npm packages | `third_party/licenses/vite-MIT.txt` plus each package's own licence file installed under `node_modules` |
| Retain MIT / Apache-2.0 notices | kyber-py, dilithium-py, cryptography, fastapi, uvicorn, pydantic, pytest | `requirements.txt` comments and this file; pip packages carry their own licence files in `site-packages/*.dist-info/` |
| Provide AGPL-3.0 text and source offer when redistributing | PyMuPDF | Not vendored here — see section 2.1 |
| No obligation | Iconify `logos` (`react.svg`) | Recorded for completeness (CC0) |
| Do not claim copyright | Every file listed in section 4 | Root `LICENSE` is scoped to our contributions — see section 1 |

---

## 6. Upstream projects deliberately **not** adopted

Considered during design and recorded here so the choice is auditable.

| Candidate | Licence | Why not adopted |
|---|---|---|
| **liboqs / liboqs-python** | MIT | No prebuilt native `liboqs` binary for Windows; every deployment machine would need a CMake/MSVC build. `core/pqc.py` is the single swap point if a hardened provider is later required. |
| **invisible-watermark** (DWT-DCT-SVD) | MIT | Experimental and effectively unmaintained; declares `torch` as a hard dependency (~GB) for a CPU path we would not use. |
| **blind_watermark** (DWT-DCT-SVD) | MIT | Applies a whole-page texture watermark; the per-recipient codeword model needs block-granular placement, so there is no behaviour-compatible drop-in. |
| **StegaStamp** | research model | Targets print-and-photo robustness, TensorFlow/GPU oriented; does not meet the offline CPU and demo-latency constraints. |
| **reedsolo** (Reed-Solomon) | MIT-0 / Unlicense | Not yet required: the current extraction path has no error-correcting layer. Reserved for future robustness work. |
| **PyCryptodome** (`Crypto.Protocol.SecretSharing`) | BSD + public domain | Shamir sharing already exists in `core/shamir.py` over `F_p` with `p = 2^256 + 297`, which guarantees every 256-bit AES key embeds with no rejection sampling. A `Crypto` package would also collide with `core/` on case-insensitive filesystems. |
| **pymerkle** | GPLv3+ | Copyleft — rejected. Merkle proofs live in `core/merkle.py` with RFC 9162-style domain separation. |
| **pikepdf** | MPL-2.0 | Not adopted: it does not render or re-flow text, which the variant pipeline requires. |
| **Hyperledger Fabric** | Apache-2.0 | Heavyweight and needs container orchestration; the "fully offline, fast in the demo" constraint favours the hash-chained log in `vault/`. |

---

## 7. How to re-verify this file

```powershell
# Python dependency licences, as resolved in your environment
.venv\Scripts\python.exe -m pip list
.venv\Scripts\python.exe -c "import kyber_py, dilithium_py, fitz, cryptography, fastapi; print('imports OK')"

# Node dependency licences
cd console\audit  ; npm ls --all ; cd ..\..
cd console\viewer ; npm ls --all ; cd ..\..

# Confirm no token from the previous project remains outside the two files that
# document it deliberately (THIRD_PARTY.md, docs/rebrand-report.md)
Get-ChildItem -Recurse -File | Select-String -Pattern 'SIGIL|Sigil|sigil'
```


