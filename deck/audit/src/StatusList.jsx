import React from 'react';
import { shortHash } from './api.js';

export function StatusList({ nodes, statuses }) {
  return (
    <div>
      {nodes.map((n) => {
        const s = statuses[n.id];
        const cls = !s ? 'warn' : s.integrity_healthy === false ? 'bad' : 'ok';
        const label = !s ? 'OFFLINE' : s.integrity_healthy === false ? 'TAMPERED' : 'ONLINE';
        return (
          <div key={n.id} className="node">
            <div className="row">
              <strong>{n.id}</strong>
              <span className={`badge ${cls}`}>{label}</span>
            </div>
            <div className="muted">{n.url}</div>
            {s ? <div className="muted">height {s.block_height} · {shortHash(s.block_hash)}</div> : null}
          </div>
        );
      })}
    </div>
  );
}
