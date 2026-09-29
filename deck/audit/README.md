# Audit Console (`deck/audit`)

**CANARY TRAP** — validator cluster telemetry, ledger explorer and forensic
sandbox. React 19 + Vite SPA, built as static files and mounted by the warden
service at `/console/`.

## What it does

- **Quorum health strip** — polls `/api/status` on all four validator nodes
  (ports 8001-8004) every 3 seconds and shows chain tip and integrity state.
- **Ledger explorer** — lists recent blocks from `/api/blocks` and, for any
  entry, fetches the Merkle audit path plus block signatures from
  `/api/proof/{entry_hash}`.
- **Tamper alarm** — a red banner appears the moment any node reports
  `integrity_healthy: false` (hash-chain or Merkle-root mismatch).
- **Forensic sandbox** — posts a path to `/api/forensics/attribute` and renders
  the live leak-attribution verdict: matched blocks, match percentage, p-value
  bound, separation margin and the full candidate ranking.
- **Attack catalogue** — the three threat scenarios and the exact commands that
  reproduce them (`gauntlet/attacks/*.py`).

## Run it

```powershell
cd deck\audit
npm install          # offline mirror or npm cache required
npm run dev          # http://localhost:5173, expects a node on 127.0.0.1:8001

npm run build        # emits dist/, which warden/service.py mounts at /console/
```

With `dist/` present, start the validator and open
`http://127.0.0.1:8001/console/`.

## Notes

- `vite.config.js` sets `base: './'` so the bundle works when served from the
  `/console/` sub-path.
- The app talks to `127.0.0.1` only; there are no CDN, font or telemetry
  requests. Everything needed is bundled.
- Scaffolded from the Vite React template (MIT); no template art remains in this app.
