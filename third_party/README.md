# third_party/ — third-party material used by CANARY TRAP

The full index with sources, versions, licences and purposes is
[`../THIRD_PARTY.md`](../THIRD_PARTY.md). This folder holds the third-party
material that is **stored in this repository**, plus the reserved patch area.

```
third_party/
  licenses/         verbatim licence texts fetched from upstream
  template-assets/  unused Vite/Iconify art, preserved out of the app trees
  unverified/       assets whose origin could not be established
  patches/          reserved for our patches against forked dependencies
```

## Dependency policy

1. Prefer an existing, maintained library over new code.
2. For each one: confirm it exists, check it is maintained, read its licence,
   and record name + version + licence + purpose in `THIRD_PARTY.md`.
3. Pin it: `requirements.txt` (Python, exact versions) or `package.json` +
   `package-lock.json` (Node).
4. Avoid AGPL/GPL unless explicitly approved. The single exception currently in
   use is **PyMuPDF (AGPL-3.0)** — flagged in `THIRD_PARTY.md` section 2.1.
5. Nothing may require network access at runtime.
6. Fork only when a patch is unavoidable, and keep the fork as a git submodule
   pinned to a fixed commit, with the patch documented in `patches/`.

## patches/

**No patches exist at present.** Nothing in this repository forks or modifies a
third-party dependency, so this folder is intentionally empty apart from its
README. Adding one requires: the submodule at a fixed commit, the `.patch` file,
and a note in `patches/README.md` stating exactly what was changed and why.

## template-assets/

Files carried over verbatim from the Vite React template
(`vitejs/vite` → `packages/create-vite/template-react`, MIT — full text in
`licenses/vite-MIT.txt`). They were not referenced by any component of the
applications, so they were moved here instead of being deleted:

| File | Origin | Licence |
|---|---|---|
| `vite.svg` | Vite logo (vite repo) | MIT |
| `vite-favicon.svg` | Vite logo, as the template's `public/favicon.svg` | MIT |
| `icons.svg` | Vite template welcome-page symbol set | MIT |
| `react.svg` | Iconify `logos` set, author Gil Barbara | CC0 1.0 |

The two apps now ship `public/favicon.svg` drawn for CANARY TRAP.

## unverified/

`hero.png` — an unused 343×361 indexed PNG with no embedded metadata and no
reference anywhere in the previous tree. Its origin is unknown, so it is kept
out of the applications and excluded from CANARY TRAP's copyright claim. See
`unverified/README.md`.
