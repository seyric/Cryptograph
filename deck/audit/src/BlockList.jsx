import React from 'react';
import { shortHash } from './api.js';

export function BlockList({ blocks, onSelect }) {
  if (!blocks.length) return <p className="muted">No blocks returned.</p>;
  return (
    <table>
      <thead><tr><th>Height</th><th>Hash</th><th>Proposer</th><th>Entries</th><th /></tr></thead>
      <tbody>
        {blocks.map((b) => (
          <tr key={b.height}>
            <td>{b.height}</td>
            <td className="mono">{shortHash(b.block_hash)}</td>
            <td>{b.proposer_id}</td>
            <td>{Array.isArray(b.entries) ? b.entries.length : 0}</td>
            <td><button className="secondary" type="button" onClick={() => onSelect(b)}>Inspect</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
