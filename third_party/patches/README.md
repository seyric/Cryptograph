# third_party/patches/ — patches against forked dependencies

## Current state: no patches

Nothing in CANARY TRAP forks, vendors or modifies a third-party dependency, so
this directory contains no `.patch` files. `core/pqc.py` exists precisely so the
post-quantum primitives can be swapped for a different provider (for example a
`liboqs`-backed adapter) **without patching** the upstream library.

## Required procedure when a patch becomes unavoidable

1. Fork the dependency and pin it as a git submodule at a fixed commit:

   ```powershell
   git submodule add https://github.com/<owner>/<repo>.git third_party/vendor/<name>
   cd third_party/vendor/<name>
   git checkout <fixed-commit-sha>
   ```

2. Keep the modification minimal and export it as a patch file here:

   ```powershell
   git format-patch -1 --stdout > ..\..\patches\<name>-<short-purpose>.patch
   ```

3. Add an entry below stating: the upstream project, the pinned commit, the file
   changed, **what changed**, and **why the change was necessary**. Say explicitly
   whether the change is a bug fix, a portability fix, or a feature.

4. Record the fork in `THIRD_PARTY.md` (component table) including its licence,
   and keep the upstream licence text in `../licenses/`.

5. Never patch in place without recording it. Never ship a patched dependency
   without its licence text and this note.

## Patch index

| Patch file | Upstream project | Pinned commit | What changed | Why |
|---|---|---|---|---|
| *(none)* | — | — | — | — |
