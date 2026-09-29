import React, { useState, useEffect } from 'react';

const DAEMON_URL = 'http://127.0.0.1:5001';

const STEPS = [
  'Unwrap ML-KEM capsule',
  'Sign DECRYPT_REQUEST',
  'Commit via quorum',
  'Reconstruct Shamir shares',
  'Assemble watermarked PDF',
];

async function readError(res, fallback) {
  try {
    const body = await res.json();
    return body.detail || fallback;
  } catch {
    return fallback;
  }
}

function shortKey(value) {
  if (!value || typeof value !== 'string') return '—';
  return value.length > 28 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function CheckIcon() {
  return (
    <svg width="9" height="9" viewBox="0 0 9 9" fill="none">
      <path d="M1.5 4.5L3.5 6.5L7.5 2.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

function SpinnerArc() {
  return (
    <svg width="9" height="9" viewBox="0 0 9 9" fill="none">
      <circle cx="4.5" cy="4.5" r="3.5" stroke="currentColor" strokeWidth="1.3" strokeDasharray="6 16" strokeLinecap="round"/>
    </svg>
  );
}

function DotIcon() {
  return <span style={{ display: 'block', width: 5, height: 5, borderRadius: '50%', background: 'currentColor', opacity: 0.35, margin: '0 auto' }} />;
}

export default function App() {
  const [identity, setIdentity]       = useState(null);
  const [connected, setConnected]     = useState(false);
  const [containerPath, setContainerPath] = useState('bench_data/DEFENCE_DIRECTIVE_2026.ct');
  const [activeDoc, setActiveDoc]     = useState(null);
  const [docInfo, setDocInfo]         = useState(null);
  const [working, setWorking]         = useState(false);
  const [step, setStep]               = useState(0);
  const [error, setError]             = useState(null);

  /* ── Identity polling ───────────────────────────────────────────── */
  useEffect(() => {
    let live = true;
    const poll = async () => {
      try {
        const res = await fetch(`${DAEMON_URL}/api/identity`);
        if (!res.ok) throw new Error(await readError(res, 'identity unavailable'));
        const data = await res.json();
        if (live) { setIdentity(data); setConnected(true); setError(null); }
      } catch {
        if (live) setConnected(false);
      }
    };
    poll();
    const timer = setInterval(poll, 5000);
    return () => { live = false; clearInterval(timer); };
  }, []);

  /* ── Decryption flow ────────────────────────────────────────────── */
  const openDocument = async () => {
    setWorking(true); setError(null); setDocInfo(null); setStep(0);
    try {
      for (let i = 1; i <= STEPS.length; i++) {
        setStep(i);
        if (i < STEPS.length) await new Promise(r => setTimeout(r, 320));
      }
      const res = await fetch(`${DAEMON_URL}/api/open_document`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_path: containerPath }),
      });
      if (!res.ok) throw new Error(await readError(res, 'decryption failed'));
      const doc = await res.json();
      setActiveDoc(doc);
      try {
        const infoRes = await fetch(`${DAEMON_URL}/api/document/${doc.doc_id}/info`);
        if (infoRes.ok) setDocInfo(await infoRes.json());
      } catch { setDocInfo(null); }
    } catch (e) {
      setError(e.message);
      setActiveDoc(null);
    } finally {
      setWorking(false);
    }
  };

  const renderUrl = activeDoc ? `${DAEMON_URL}${activeDoc.render_url}` : null;

  return (
    <div>
      {/* ── Top Bar ────────────────────────────────────────────────── */}
      <header className="topbar">
        <div className="topbar-logo">🔐</div>
        <div className="topbar-text">
          <h1>CANARY TRAP · Recipient Viewer</h1>
          <p>Log-before-key decryption — keys released only after quorum commits the signed request</p>
        </div>
        <div className="topbar-status">
          <span className={`badge ${connected ? 'ok' : 'warn'}`}>
            {connected ? 'DAEMON ONLINE' : 'DAEMON OFFLINE'}
          </span>
        </div>
      </header>

      <main className="page">

        {/* ── Recipient Card ────────────────────────────────────────── */}
        <section className="card">
          <h2>Recipient Identity</h2>
          <div className="glow-divider" />

          <div className="key-row">
            <span className="key-label">ID</span>
            <span className="muted">{identity ? identity.recipient_id : 'ALICE (assumed)'}</span>
          </div>
          <div className="key-row">
            <span className="key-label">ML-KEM</span>
            <span className="mono">{shortKey(identity && identity.ml_kem_public_key)}</span>
          </div>
          <div className="key-row">
            <span className="key-label">ML-DSA</span>
            <span className="mono">{shortKey(identity && identity.ml_dsa_public_key)}</span>
          </div>
        </section>

        {/* ── Open Container Card ──────────────────────────────────── */}
        <section className="card">
          <h2>Open a Container</h2>
          <div className="glow-divider" />

          <label className="muted" htmlFor="container" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
            Container path visible to the daemon process
          </label>
          <div className="row">
            <input
              id="container"
              value={containerPath}
              onChange={e => setContainerPath(e.target.value)}
              placeholder="path/to/file.ct"
              style={{ flex: 1 }}
            />
            <button
              type="button"
              className="secondary"
              onClick={() => setContainerPath('bench_data/DEFENCE_DIRECTIVE_2026.ct')}
            >
              Demo file
            </button>
          </div>

          <div className="row" style={{ marginTop: 14 }}>
            <button
              type="button"
              id="btn-decrypt"
              onClick={openDocument}
              disabled={working || !containerPath}
            >
              {working ? 'Decrypting…' : '⚡ Decrypt and Open'}
            </button>
            {activeDoc && (
              <button
                type="button"
                className="secondary"
                onClick={() => { setActiveDoc(null); setDocInfo(null); setStep(0); }}
              >
                Close
              </button>
            )}
          </div>

          {/* Decryption steps */}
          {(working || step > 0) && (
            <div style={{ marginTop: 16 }}>
              <ul className="steps-list">
                {STEPS.map((label, idx) => {
                  const n = idx + 1;
                  const isDone   = !working && step >= n;
                  const isActive = working && step === n;
                  const isPend   = step < n;
                  return (
                    <li key={label} className={isDone ? 'done' : isActive ? 'active' : ''}>
                      <span className="step-icon">
                        {isDone   ? <CheckIcon />   :
                         isActive ? <SpinnerArc />  :
                                    <DotIcon />}
                      </span>
                      {label}
                    </li>
                  );
                })}
              </ul>
              <div className="progress" style={{ marginTop: 14 }}>
                <div style={{ width: `${(step / STEPS.length) * 100}%` }} />
              </div>
              {working && (
                <p className="step-label" style={{ marginTop: 8 }}>
                  Step <span>{Math.min(step, STEPS.length)}</span> of {STEPS.length} — {STEPS[Math.max(step - 1, 0)]}
                </p>
              )}
            </div>
          )}

          {error && <div className="alert error">⚠ {error}</div>}
        </section>

        {/* ── Active Document Card ──────────────────────────────────── */}
        {activeDoc && (
          <section className="card">
            <div className="row" style={{ marginBottom: 14 }}>
              <h2 style={{ margin: 0 }}>{activeDoc.doc_id}</h2>
              <span className="badge ok">{activeDoc.status}</span>
              <span className="badge">block #{activeDoc.block_height}</span>
            </div>
            <div className="glow-divider" />

            <div className="key-row">
              <span className="key-label">SESSION</span>
              <span className="mono">{activeDoc.session_entry_hash}</span>
            </div>

            {docInfo && (
              <pre className="dump">{JSON.stringify(docInfo, null, 2)}</pre>
            )}
            {renderUrl && (
              <iframe
                title={`Decrypted ${activeDoc.doc_id}`}
                src={renderUrl}
                className="doc-frame"
              />
            )}
          </section>
        )}

      </main>
    </div>
  );
}
