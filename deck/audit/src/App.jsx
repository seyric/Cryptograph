import React, { useCallback, useEffect, useState } from 'react';
import { NODES } from './api.js';
import { StatusList } from './StatusList.jsx';
import { BlockList } from './BlockList.jsx';
import { ForensicPanel } from './ForensicPanel.jsx';

async function getJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    // Surface the server's own explanation: a bare "HTTP 500" hides whether the
    // ledger lookup failed, the file was missing, or the watermark gate refused.
    let detail = '';
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      detail = res.statusText;
    }
    throw new Error(`HTTP ${res.status}${detail ? ` — ${detail}` : ''}`);
  }
  return res.json();
}

const TABS = [
  { key: 'status',    label: '⬡ Status'    },
  { key: 'blocks',    label: '▤ Blocks'    },
  { key: 'forensics', label: '⌖ Forensics' },
];

export default function App() {
  const [node, setNode]       = useState(NODES[0]);
  const [tab, setTab]         = useState('status');
  const [statuses, setStatuses] = useState({});
  const [blocks, setBlocks]   = useState([]);
  const [selected, setSelected] = useState(null);
  const [pdfPath, setPdfPath] = useState('bench_data/alice_decrypted.pdf');
  const [forensic, setForensic] = useState(null);
  const [error, setError]     = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  const refresh = useCallback(async () => {
    setError(null);
    const next = {};
    await Promise.all(NODES.map(async (n) => {
      try { next[n.id] = await getJson(`${n.url}/api/status`); }
      catch { next[n.id] = null; }
    }));
    setStatuses(next);
    try {
      setBlocks(await getJson(`${node.url}/api/blocks?limit=25`));
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (e) { setError(e.message); }
  }, [node]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, [refresh]);

  const onlineCount = NODES.filter(n => statuses[n.id] != null).length;

  return (
    <div>
      {/* ── Top Bar ─────────────────────────────────────────────────── */}
      <header className="topbar">
        <div className="topbar-logo">⬡</div>
        <div>
          <h1>CANARY TRAP · Audit Console</h1>
          <p>Real-time quorum ledger — zero-trust provenance verification</p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className={`badge ${onlineCount > 0 ? 'ok' : 'bad'}`}>
            {onlineCount}/{NODES.length} NODES
          </span>
          <button type="button" className="secondary" onClick={refresh} style={{ fontSize: 11, padding: '5px 12px' }}>
            ↻ Refresh
          </button>
        </div>
      </header>

      <main className="page">
        {error && <div className="alert error">⚠ {error}</div>}

        <div className="tabs">
          {TABS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              className={tab === key ? 'active' : 'secondary'}
              onClick={() => setTab(key)}
            >
              {label}
            </button>
          ))}
          {lastRefresh && (
            <span className="muted" style={{ fontSize: 11, marginLeft: 'auto', alignSelf: 'center' }}>
              Last updated {lastRefresh}
            </span>
          )}
        </div>

        <div className="grid two">
          {/* ── Node Sidebar ────────────────────────────────────────── */}
          <div>
            <div className="card">
              <h2>Cluster Nodes</h2>
              <div className="glow-divider" />
              {NODES.map((n) => (
                <div key={n.id} className="node" style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
                  onClick={() => setNode(n)}>
                  <input
                    type="radio"
                    checked={node.id === n.id}
                    onChange={() => setNode(n)}
                    style={{ accentColor: '#e2e8f0' }}
                  />
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 12, flex: 1 }}>{n.id}</span>
                  <span className={`badge ${statuses[n.id] ? 'ok' : 'bad'}`}>
                    {statuses[n.id] ? 'UP' : 'DOWN'}
                  </span>
                </div>
              ))}
            </div>
            <StatusList nodes={NODES} statuses={statuses} />
          </div>

          {/* ── Main Panel ──────────────────────────────────────────── */}
          <div>
            {tab === 'status' && (
              <div className="card">
                <h2>Node Status — {node.id}</h2>
                <div className="glow-divider" />
                <pre className="dump">{JSON.stringify(statuses[node.id], null, 2) ?? 'No data — node offline'}</pre>
              </div>
            )}
            {tab === 'blocks' && (
              <div className="card">
                <h2>Block Log</h2>
                <div className="glow-divider" />
                <BlockList blocks={blocks} onSelect={setSelected} />
                {selected && <pre className="dump">{JSON.stringify(selected, null, 2)}</pre>}
              </div>
            )}
            {tab === 'forensics' && (
              <div className="card">
                <h2>Forensic Attribution</h2>
                <div className="glow-divider" />
                <ForensicPanel
                  pdfPath={pdfPath}
                  setPdfPath={setPdfPath}
                  result={forensic}
                  onRun={async () => {
                    try {
                      setForensic(await getJson(
                        `${node.url}/api/forensics/attribute`,
                        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pdf_path: pdfPath }) }
                      ));
                    } catch (err) {
                      // A failed attribution must be visible, not a silent no-op.
                      setForensic({ status: 'REQUEST_FAILED', verdict: err.message });
                    }
                  }}
                />
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
