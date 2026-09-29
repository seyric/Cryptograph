# Recipient Viewer (`deck/viewer`)

**CANARY TRAP** — the recipient-side portal: identity card, "log before key"
decryption walkthrough, provenance summary and the watermarked document. React 19 +
Vite SPA, built as static files and mounted by the bridge daemon at `/`.

## What it does

- **Identity card** — polls `GET /api/identity` on the local daemon
  (`127.0.0.1:5001`) and shows the recipient ID plus public-key fingerprints.
- **Log-before-key stepper** — a five-stage visual walkthrough of what the
  daemon is actually doing: unwrap the ML-KEM capsule, sign the
  `DECRYPT_REQUEST`, commit via quorum consensus, reconstruct the Shamir shares
  by Lagrange interpolation, then stitch the codeword-selected variants.
- **Provenance HUD** — committed block height, session entry hash and block hash
  for the open document, read from `GET /api/document/{doc_id}/info`.
- **Document view** — an `<iframe>` pointing at
  `GET /api/document/{doc_id}/render`, which streams the watermarked PDF from
  daemon memory. The browser's own PDF viewer renders it; nothing is written to
  disk by the app.
- **Forensic lens** — explains the micro-typographic word-spacing delta
  (`Tw`) that carries the recipient's codeword.

## Run it

```powershell
# 1. recipient daemon (the viewer is mounted by it)
python -m uvicorn bridge.service:app --host 127.0.0.1 --port 5001

# 2a. dev server with hot reload
cd deck\viewer
npm install
npm run dev          # http://localhost:5173

# 2b. or build and let the daemon serve it
npm run build        # emits dist/, which bridge/service.py mounts at /
```

Then open `http://127.0.0.1:5001/`.

## Notes

- Requests go to `127.0.0.1:5001` only. No CDN, font or analytics requests.
- The app does **not** bundle a PDF renderer; it relies on the browser's native
  PDF support, so the viewer must be a browser with a built-in PDF viewer.
- Scaffolded from the Vite React template (MIT); no template art remains in this app.
