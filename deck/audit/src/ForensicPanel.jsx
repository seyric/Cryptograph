import React from 'react';

export function ForensicPanel({ pdfPath, setPdfPath, onRun, result }) {
  return (
    <div className="card">
      <h2>Forensic attribution</h2>
      <div className="row">
        <input value={pdfPath} onChange={(e) => setPdfPath(e.target.value)} style={{ flex: 1 }} />
        <button type="button" onClick={onRun}>Attribute</button>
      </div>
      {result ? <pre className="dump">{JSON.stringify(result, null, 2)}</pre> : null}
    </div>
  );
}
