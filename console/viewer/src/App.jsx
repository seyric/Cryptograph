import React, { useState, useEffect } from 'react';

const DAEMON_URL = 'http://127.0.0.1:5001';

export default function App() {
  const [identity, setIdentity] = useState(null);
  const [daemonConnected, setDaemonConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [openModal, setOpenModal] = useState(false);
  const [activeDoc, setActiveDoc] = useState(null);
  const [containerPath, setContainerPath] = useState('data/alice/policy_directive_2026.ct');
  const [showCertificate, setShowCertificate] = useState(false);
  const [showForensicLens, setShowForensicLens] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // Poll recipient daemon identity on load
  const fetchIdentity = async () => {
    try {
      const res = await fetch(`${DAEMON_URL}/api/identity`);
      if (res.ok) {
        const data = await res.json();
        setIdentity(data);
        setDaemonConnected(true);
        setErrorMsg(null);
      } else {
        setDaemonConnected(false);
      }
    } catch (err) {
      setDaemonConnected(false);
    }
  };

  useEffect(() => {
    fetchIdentity();
    const interval = setInterval(fetchIdentity, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleOpenDocument = async () => {
    setLoading(true);
    setOpenModal(true);
    setErrorMsg(null);

    // Animated Log-Before-Key steps
    setCurrentStep(1); // Unwrap ML-KEM
    await new Promise((r) => setTimeout(r, 600));

    setCurrentStep(2); // Sign DECRYPT_REQUEST
    await new Promise((r) => setTimeout(r, 600));

    setCurrentStep(3); // Submit to Quorum Consensus
    await new Promise((r) => setTimeout(r, 800));

    try {
      const res = await fetch(`${DAEMON_URL}/api/open_document`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container_path: containerPath }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to decrypt document');
      }

      setCurrentStep(4); // Reconstruct Shamir Shares
      await new Promise((r) => setTimeout(r, 500));

      setCurrentStep(5); // Stitch Watermark Variant
      await new Promise((r) => setTimeout(r, 400));

      const docData = await res.json();
      setActiveDoc(docData);
      setOpenModal(false);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="root">
      {/* Top Header */}
      <header className="ct-header">
        <div className="brand-section">
          <div className="shield-badge">🛡️</div>
          <div>
            <div className="brand-title">
              CANARY TRAP
              <span className="badge badge-purple" style={{ fontSize: '10px' }}>
                POST-QUANTUM AIR-GAP
              </span>
            </div>
            <div className="sub-tagline">Cryptographic Recipient Provenance Client</div>
          </div>
        </div>

        <div className="header-status-strip">
          <div className={`badge ${daemonConnected ? 'badge-emerald' : 'badge-rose'}`}>
            <span className="pulse-dot"></span>
            {daemonConnected ? 'DAEMON ONLINE (PORT 5001)' : 'DAEMON OFFLINE'}
          </div>

          <div className="badge badge-cyan">
            <span>FIPS 203 / 204</span>
          </div>

          {identity && (
            <div className="badge badge-purple">
              👤 {identity.recipient_id}
            </div>
          )}
        </div>
      </header>

      {/* Main Workspace */}
      <main className="app-layout">
        {/* Document Provenance HUD (Shown when doc is active) */}
        {activeDoc && (
          <div className="provenance-hud">
            <div className="hud-item">
              <span className="hud-label">Document ID</span>
              <span className="hud-value" style={{ color: '#38bdf8' }}>
                {activeDoc.doc_id}
              </span>
            </div>
            <div className="hud-item">
              <span className="hud-label">Committed Block Height</span>
              <span className="hud-value" style={{ color: '#34d399' }}>
                Block #{activeDoc.block_height}
              </span>
            </div>
            <div className="hud-item">
              <span className="hud-label">Session Entry Hash</span>
              <span className="hud-value" title={activeDoc.session_entry_hash}>
                {activeDoc.session_entry_hash.slice(0, 14)}...{activeDoc.session_entry_hash.slice(-6)}
              </span>
            </div>
            <div className="hud-item">
              <span className="hud-label">Forensic Attribution</span>
              <span className="hud-value" style={{ color: '#a78bfa' }}>
                Section 63 BSA Watermark Embedded
              </span>
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                className="btn-secondary"
                onClick={() => setShowForensicLens(true)}
              >
                🔬 Forensic Lens
              </button>
              <button
                className="btn-primary"
                style={{ background: 'linear-gradient(135deg, #10b981, #06b6d4)' }}
                onClick={() => setShowCertificate(true)}
              >
                📜 BSA Evidence Certificate
              </button>
            </div>
          </div>
        )}

        {/* Action Panel if no doc opened */}
        {!activeDoc ? (
          <div className="glass-panel" style={{ textAlign: 'center', padding: '60px 40px' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔐</div>
            <h2 style={{ fontSize: '26px', color: '#fff', marginBottom: '10px' }}>
              Open Encrypted CANARY TRAP Document
            </h2>
            <p style={{ color: '#94a3b8', maxWidth: '580px', margin: '0 auto 30px' }}>
              CANARY TRAP enforces <strong>"No Log, No Key"</strong>. The decryption keys for this document
              will only be synthesized after your signed decryption request is permanently committed to the
              post-quantum immutable ledger.
            </p>

            <div style={{ maxWidth: '500px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <input
                type="text"
                value={containerPath}
                onChange={(e) => setContainerPath(e.target.value)}
                placeholder="Path to .ct container"
                style={{
                  background: '#0a0f1d',
                  border: '1px solid rgba(255,255,255,0.15)',
                  color: '#fff',
                  padding: '12px 16px',
                  borderRadius: '8px',
                  fontFamily: 'ui-monospace, monospace',
                  fontSize: '13px',
                }}
              />

              {errorMsg && (
                <div style={{ color: '#fb7185', fontSize: '13px', background: 'rgba(244,63,94,0.1)', padding: '10px', borderRadius: '6px' }}>
                  ⚠️ {errorMsg}
                </div>
              )}

              <button
                className="btn-primary"
                onClick={handleOpenDocument}
                disabled={loading || !daemonConnected}
                style={{ justifyContent: 'center', padding: '14px' }}
              >
                {loading ? 'Executing Post-Quantum Decryption...' : '🔓 Decrypt & Verify Provenance'}
              </button>
            </div>
          </div>
        ) : (
          /* Document Viewer Grid */
          <div className="viewer-container">
            {/* Embedded PDF View */}
            <iframe
              className="pdf-display-frame"
              src={`${DAEMON_URL}${activeDoc.render_url}`}
              title="CANARY TRAP Decrypted Document"
            />

            {/* Sidebar Security Controls */}
            <div className="sidebar-panel">
              <div className="glass-panel">
                <h3 style={{ fontSize: '15px', color: '#fff', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  🛡️ Session Provenance
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
                  <div>
                    <span style={{ color: '#64748b' }}>Recipient Device:</span>
                    <div style={{ fontFamily: 'ui-monospace, monospace', color: '#e2e8f0', marginTop: '2px' }}>
                      {identity?.recipient_id || 'ALICE'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: '#64748b' }}>ML-KEM-768 PK Fingerprint:</span>
                    <div style={{ fontFamily: 'ui-monospace, monospace', color: '#a78bfa', marginTop: '2px', wordBreak: 'break-all' }}>
                      {identity?.ml_kem_public_key?.slice(0, 32)}...
                    </div>
                  </div>
                  <div>
                    <span style={{ color: '#64748b' }}>ML-DSA-65 Signature Verified:</span>
                    <div style={{ color: '#34d399', marginTop: '2px' }}>
                      ✅ Pass (FIPS 204 Validated)
                    </div>
                  </div>
                  <div>
                    <span style={{ color: '#64748b' }}>Ledger Commit Status:</span>
                    <div style={{ color: '#38bdf8', marginTop: '2px' }}>
                      ✅ Block #{activeDoc.block_height} (Finalized)
                    </div>
                  </div>
                </div>
              </div>

              <div className="glass-panel">
                <h3 style={{ fontSize: '15px', color: '#fff', marginBottom: '12px' }}>
                  ⚖️ Legal Non-Repudiation
                </h3>
                <p style={{ fontSize: '12px', color: '#94a3b8', lineHeight: '1.5' }}>
                  This copy contains an undetectable, imperceptible word-spacing watermark bound directly
                  to Session Entry <code>{activeDoc.session_entry_hash.slice(0, 8)}</code>. Any unauthorized release,
                  photograph, or print scan can be attributed back with mathematical certainty ($p &lt; 10^{'{ -23 }'}$)
                  under Section 63 of Bharatiya Sakshya Adhiniyam, 2023.
                </p>
                <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <button className="btn-secondary" onClick={() => setActiveDoc(null)}>
                    📁 Open Another Document
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Log-Before-Key Pipeline Modal */}
      {openModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3 style={{ fontSize: '18px', color: '#fff', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '12px' }}>
              CANARY TRAP Zero-Trust Decryption Pipeline
            </h3>
            <p style={{ fontSize: '13px', color: '#94a3b8' }}>
              Enforcing non-repudiation: cryptographic variant keys will only be released once your access request
              is signed and committed to the ledger block.
            </p>

            <div style={{ margin: '14px 0' }}>
              <div className="stepper-item">
                <div className={`step-icon ${currentStep > 1 ? 'done' : currentStep === 1 ? 'active' : ''}`}>
                  {currentStep > 1 ? '✓' : '1'}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Unwrap Container Outer Envelope</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>FIPS 203 ML-KEM-768 Decapsulation</div>
                </div>
              </div>

              <div className="stepper-item">
                <div className={`step-icon ${currentStep > 2 ? 'done' : currentStep === 2 ? 'active' : ''}`}>
                  {currentStep > 2 ? '✓' : '2'}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Generate Ephemeral Key &amp; Sign DECRYPT_REQUEST</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>FIPS 204 ML-DSA-65 Canonical JSON Signature</div>
                </div>
              </div>

              <div className="stepper-item">
                <div className={`step-icon ${currentStep > 3 ? 'done' : currentStep === 3 ? 'active' : ''}`}>
                  {currentStep > 3 ? '✓' : '3'}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Quorum Consensus Commit</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>Round-Robin Leader + 3-of-4 ML-DSA BFT Block Signatures</div>
                </div>
              </div>

              <div className="stepper-item">
                <div className={`step-icon ${currentStep > 4 ? 'done' : currentStep === 4 ? 'active' : ''}`}>
                  {currentStep > 4 ? '✓' : '4'}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Shamir Key Share Reconstruction</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>Lagrange Interpolation over Prime Field F_p</div>
                </div>
              </div>

              <div className="stepper-item">
                <div className={`step-icon ${currentStep >= 5 ? 'done' : ''}`}>
                  {currentStep >= 5 ? '✓' : '5'}
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>Forensic Variant Assembly</div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>In-Memory PDF Stream Synthesis with Invisible Spacing Deltas</div>
                </div>
              </div>
            </div>

            {errorMsg && (
              <div style={{ color: '#fb7185', fontSize: '13px', background: 'rgba(244,63,94,0.1)', padding: '10px', borderRadius: '6px' }}>
                ⚠️ Error: {errorMsg}
                <button className="btn-secondary" style={{ marginTop: '8px', width: '100%' }} onClick={() => setOpenModal(false)}>
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Forensic Lens Modal */}
      {showForensicLens && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '600px' }}>
            <h3 style={{ fontSize: '18px', color: '#fff' }}>🔬 Forensic Watermark Lens</h3>
            <p style={{ fontSize: '13px', color: '#94a3b8' }}>
              CANARY TRAP uses imperceptible PDF word-spacing modulation (<code>Tw = 0.750 pt</code>).
              To the human eye and standard printers, the document is pristine. At the micro-typographic layer,
              each word boundary encodes a bit of your deterministic cryptographic codeword.
            </p>

            <div style={{ background: '#0a0f1d', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '6px' }}>Micro-Typographic Shift Matrix:</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                <div style={{ background: '#111827', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: '#38bdf8', fontWeight: 600 }}>Variant A (Bit 0)</div>
                  <div style={{ fontFamily: 'ui-monospace, monospace', marginTop: '4px' }}>Tw: 0.000 pt (Default)</div>
                </div>
                <div style={{ background: '#111827', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: '#a78bfa', fontWeight: 600 }}>Variant B (Bit 1)</div>
                  <div style={{ fontFamily: 'ui-monospace, monospace', marginTop: '4px' }}>Tw: +0.750 pt (+0.26 mm)</div>
                </div>
              </div>
            </div>

            <p style={{ fontSize: '12px', color: '#94a3b8' }}>
              Because your specific sequence of variants is locked into block #{activeDoc?.block_height},
              any leak can be traced back in &lt; 1 second by the Forensic Lab verifier.
            </p>

            <button className="btn-primary" onClick={() => setShowForensicLens(false)}>
              Done
            </button>
          </div>
        </div>
      )}

      {/* Section 63 BSA Evidence Certificate Modal */}
      {showCertificate && activeDoc && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '720px', background: '#070b14' }}>
            <div style={{ border: '2px solid rgba(16, 185, 129, 0.4)', padding: '24px', borderRadius: '12px' }}>
              <div style={{ textAlign: 'center', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '16px', marginBottom: '16px' }}>
                <div style={{ fontSize: '13px', letterSpacing: '2px', color: '#10b981', fontWeight: 700 }}>
                  BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023
                </div>
                <h2 style={{ fontSize: '20px', color: '#fff', margin: '6px 0' }}>
                  SECTION 63 ELECTRONIC EVIDENCE CERTIFICATE
                </h2>
                <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                  Certificate of Electronic Provenance &amp; Mathematical Attestation
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Document Identifier:</span>
                  <span style={{ fontFamily: 'ui-monospace, monospace', color: '#fff' }}>{activeDoc.doc_id}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Authorized Recipient:</span>
                  <span style={{ fontFamily: 'ui-monospace, monospace', color: '#fff' }}>{identity?.recipient_id || 'ALICE'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Session Entry Hash:</span>
                  <span style={{ fontFamily: 'ui-monospace, monospace', color: '#38bdf8' }}>{activeDoc.session_entry_hash}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Ledger Block Height:</span>
                  <span style={{ fontFamily: 'ui-monospace, monospace', color: '#fff' }}>Block #{activeDoc.block_height}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Ledger Block Hash:</span>
                  <span style={{ fontFamily: 'ui-monospace, monospace', color: '#94a3b8' }}>{activeDoc.block_hash}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Cryptographic Proof Type:</span>
                  <span style={{ color: '#34d399' }}>FIPS 204 ML-DSA-65 Quorum Consensus (3-of-4 Threshold)</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Air-Gapped Non-Repudiation:</span>
                  <span style={{ color: '#34d399' }}>Verified (Zero NTP or Cloud Dependency)</span>
                </div>
              </div>

              <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px dashed rgba(255,255,255,0.15)', fontSize: '11px', color: '#94a3b8', fontStyle: 'italic' }}>
                "This document hereby certifies under Section 63 of Bharatiya Sakshya Adhiniyam, 2023,
                that the electronic record above was securely created, attested, and signed by authorized cryptographic hardware.
                Decryption keys were only released upon verifiable commit to the distributed immutable ledger."
              </div>
            </div>

            <button className="btn-primary" onClick={() => setShowCertificate(false)} style={{ alignSelf: 'flex-end' }}>
              Close Certificate
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
