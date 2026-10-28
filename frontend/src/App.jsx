import React, { useState, useEffect, useCallback } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  ShieldAlert,
  Clock,
  RefreshCw, 
  FileCode, 
  Check, 
  Copy, 
  X,
  AlertCircle
} from 'lucide-react';
import './App.css';

const SCENARIOS = [
  {
    id: 'happy_path',
    name: '1. Happy path',
    tag: 'Valid',
    desc: 'Valid sequence 1→2→3→4 reaches CONTAINED. Ed25519 signatures, hash chain, Poseidon commitment, and Groth16 proof all verify.',
    color: '#166A43'
  },
  {
    id: 'policy_denial',
    name: '2. Policy gate denial',
    tag: 'Policy',
    desc: 'Adversary requests out-of-order action ISOLATE_SERVICE from state 0. Blocked before execution without state mutation.',
    color: '#8A4E00'
  },
  {
    id: 'tampered_receipt',
    name: '3. Tampered receipt',
    tag: 'Tampering',
    desc: 'Adversary modifies target_id in signed receipt. Independent Ed25519 signature and SHA-256 chain verification fail.',
    color: '#A32117'
  },
  {
    id: 'broken_chain',
    name: '4. Broken hash chain',
    tag: 'Tampering',
    desc: 'Receipt #3 omitted from sequence. SHA-256 backward linkage and commitment binding checks fail closed.',
    color: '#A32117'
  },
  {
    id: 'replay_attack',
    name: '5. Cross-run replay',
    tag: 'Replay',
    desc: 'Valid Groth16 proof from foreign run paired with receipts. Independent commitment binding check detects the mismatch.',
    color: '#5B21B6'
  },
  {
    id: 'tampered_proof',
    name: '6. Tampered proof signal',
    tag: 'Proof fault',
    desc: 'Public Poseidon commitment altered inside proof. Independent pairing check and binding both reject the proof.',
    color: '#A32117'
  }
];

const GATES = [
  { key: 'policy_check', id: 1, title: 'Policy gate', desc: 'Runtime FSM transition rules and target allowlist verification' },
  { key: 'execution_check', id: 2, title: 'Simulated execution', desc: 'State mutation inside controlled mock sandbox environment' },
  { key: 'receipt_signatures', id: 3, title: 'Receipt signatures', desc: 'Ed25519 digital signature verified for every action receipt' },
  { key: 'hash_chain', id: 4, title: 'Hash chain integrity', desc: 'SHA-256 backward hash link continuity and monotonic sequence' },
  { key: 'commitment_binding', id: 5, title: 'Commitment binding', desc: 'Poseidon(5) sequence commitment bound to circuit public inputs' },
  { key: 'proof_generation', id: 6, title: 'ZK proof generation', desc: 'Groth16 prover execution on Circom fsm_v1 circuit' },
  { key: 'zk_verification', id: 7, title: 'Independent ZK verification', desc: 'Groth16 pairing check evaluated with pinned verification key' }
];

const FSM_STEPS = [
  { id: 0, codeName: 'DETECTED', action: 'INIT' },
  { id: 1, codeName: 'IP_BLOCKED', action: 'BLOCK_IP' },
  { id: 2, codeName: 'CREDENTIAL_ROTATED', action: 'ROTATE_CRED' },
  { id: 3, codeName: 'SERVICE_ISOLATED', action: 'ISOLATE_SVC' },
  { id: 4, codeName: 'CONTAINED', action: 'CONFIRM' }
];

function truncateMiddle(str, front = 6, back = 6) {
  if (!str) return '—';
  if (str.length <= front + back + 3) return str;
  return `${str.slice(0, front)}...${str.slice(-back)}`;
}

export default function App() {
  const [systemMeta, setSystemMeta] = useState(null);
  const [backendStatus, setBackendStatus] = useState('connecting'); // 'connecting' | 'online' | 'offline'
  const [selectedScenario, setSelectedScenario] = useState('happy_path');
  const [isRunning, setIsRunning] = useState(false);
  const [runData, setRunData] = useState(null);
  const [apiError, setApiError] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTab, setModalTab] = useState('report');
  const [copiedKey, setCopiedKey] = useState(null);

  // Fetch initial system status
  const fetchSystemStatus = useCallback(async () => {
    setBackendStatus('connecting');
    setApiError(null);
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSystemMeta(data);
      setBackendStatus('online');
    } catch (err) {
      console.warn('Backend status check failed:', err.message);
      setBackendStatus('offline');
      setApiError('Unable to connect to backend service. Start the server via `npm start`.');
    }
  }, []);

  useEffect(() => {
    fetchSystemStatus();
  }, [fetchSystemStatus]);

  // Escape key handler for modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && modalOpen) {
        setModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [modalOpen]);

  // Execute scenario
  const handleExecuteScenario = async (scenarioId = selectedScenario) => {
    if (isRunning) return;
    setIsRunning(true);
    setApiError(null);
    setSelectedScenario(scenarioId);

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId })
      });
      if (!res.ok) throw new Error(`Execution error: HTTP ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setRunData(data);
      setBackendStatus('online');
    } catch (err) {
      setApiError(err.message || 'Simulation execution failed');
      setBackendStatus('offline');
    } finally {
      setIsRunning(false);
    }
  };

  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const report = runData?.verificationReport || {};
  const receipts = runData?.receipts || [];
  const proofData = runData?.proofData || null;
  const logs = runData?.logs || [];

  // Honest overall evaluation:
  // All 7 gates must explicitly be PASS for allPassed
  const hasRun = Boolean(runData);
  const isDenied = report.policy_check === 'DENIED';
  const allPassed = hasRun && 
    report.policy_check === 'PASS' &&
    report.execution_check === 'PASS' &&
    report.receipt_signatures === 'PASS' &&
    report.hash_chain === 'PASS' &&
    report.commitment_binding === 'PASS' &&
    report.proof_generation === 'PASS' &&
    report.zk_verification === 'PASS';

  // Honest Poseidon commitment value:
  // Derived from proofData.commitment or verified public input if binding passed
  const computedCommitment = runData?.proofData?.commitment 
    || report.details?.expectedCommitment 
    || (report.commitment_binding === 'PASS' && proofData?.publicSignals?.[1] ? proofData.publicSignals[1] : null);

  const renderStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="status-badge badge-pass" aria-label="Status: Pass">
            <CheckCircle2 size={13} aria-hidden="true" />
            PASS
          </span>
        );
      case 'FAIL':
        return (
          <span className="status-badge badge-fail" aria-label="Status: Fail">
            <XCircle size={13} aria-hidden="true" />
            FAIL
          </span>
        );
      case 'DENIED':
        return (
          <span className="status-badge badge-denied" aria-label="Status: Denied by policy">
            <ShieldAlert size={13} aria-hidden="true" />
            DENIED
          </span>
        );
      case 'BLOCKED':
        return (
          <span className="status-badge badge-blocked" aria-label="Status: Blocked">
            <AlertTriangle size={13} aria-hidden="true" />
            BLOCKED
          </span>
        );
      default:
        return (
          <span className="status-badge badge-notrun" aria-label="Status: Not run">
            <Clock size={13} aria-hidden="true" />
            NOT_RUN
          </span>
        );
    }
  };

  return (
    <div className="app-shell">
      {/* Sticky Header */}
      <header className="site-header">
        <div className="container-boxed header-inner">
          <div className="brand-group">
            <img 
              src="/logo.png" 
              alt="VeriRespond — AI Defends. Zero-Knowledge Proves It." 
              className="brand-logo-img" 
            />
          </div>

          <div className="header-actions">
            {systemMeta?.circuit_manifest_hash && (
              <div className="meta-chip" title={`Manifest SHA-256: ${systemMeta.circuit_manifest_hash}`}>
                <span className="meta-chip-label">Manifest</span>
                <span className="meta-chip-val">{truncateMiddle(systemMeta.circuit_manifest_hash, 6, 4)}</span>
                <button 
                  className="icon-copy-btn" 
                  onClick={() => handleCopy(systemMeta.circuit_manifest_hash, 'manifest')}
                  aria-label="Copy circuit manifest hash"
                >
                  {copiedKey === 'manifest' ? <Check size={12} color="#166A43" /> : <Copy size={12} />}
                </button>
              </div>
            )}

            {systemMeta?.verification_key_hash && (
              <div className="meta-chip" title={`VKey SHA-256: ${systemMeta.verification_key_hash}`}>
                <span className="meta-chip-label">VKey</span>
                <span className="meta-chip-val">{truncateMiddle(systemMeta.verification_key_hash, 6, 4)}</span>
                <button 
                  className="icon-copy-btn" 
                  onClick={() => handleCopy(systemMeta.verification_key_hash, 'vkey')}
                  aria-label="Copy verification key hash"
                >
                  {copiedKey === 'vkey' ? <Check size={12} color="#166A43" /> : <Copy size={12} />}
                </button>
              </div>
            )}

            <div className={`system-status-pill ${backendStatus}`} aria-label={`Backend status: ${backendStatus}`}>
              <span className="status-dot" aria-hidden="true"></span>
              <span>
                {backendStatus === 'online' ? 'Backend online' : backendStatus === 'offline' ? 'Backend offline' : 'Connecting'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* API Error Notification */}
      {apiError && (
        <div className="container-boxed" style={{ marginTop: '16px' }}>
          <div style={{
            background: 'var(--status-fail-bg)',
            border: '1px solid var(--status-fail-border)',
            borderRadius: '12px',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            color: 'var(--status-fail-text)',
            fontSize: '13px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertCircle size={16} />
              <span>{apiError}</span>
            </div>
            <button
              className="btn-secondary"
              style={{ width: 'auto', padding: '6px 12px', fontSize: '12px' }}
              onClick={fetchSystemStatus}
            >
              Try again
            </button>
          </div>
        </div>
      )}

      {/* Main Two-Column Layout */}
      <main className="container-boxed main-layout">
        
        {/* Left Sidebar: Scenario Selector & Execution Controls */}
        <aside className="sidebar-panel" aria-label="Scenario Selection">
          <div className="sidebar-header">
            <h2 className="section-title">Scenarios</h2>
            <span className="section-hint">Select a playbook</span>
          </div>

          <div className="scenarios-scrollable" role="radiogroup" aria-label="Playbook scenarios">
            {SCENARIOS.map((sc) => {
              const isSelected = selectedScenario === sc.id;
              return (
                <button
                  key={sc.id}
                  className={`scenario-button ${isSelected ? 'selected' : ''}`}
                  onClick={() => handleExecuteScenario(sc.id)}
                  disabled={isRunning}
                  role="radio"
                  aria-checked={isSelected}
                  aria-pressed={isSelected}
                >
                  <div className="scenario-top-row">
                    <div className="scenario-title-wrap">
                      <span className="scenario-dot" style={{ backgroundColor: sc.color }} aria-hidden="true" />
                      <span className="scenario-name">{sc.name}</span>
                    </div>
                    <span className="scenario-tag">{sc.tag}</span>
                  </div>
                  <p className="scenario-description">{sc.desc}</p>
                </button>
              );
            })}
          </div>

          <div className="sidebar-actions">
            <button
              className="btn-primary"
              onClick={() => handleExecuteScenario(selectedScenario)}
              disabled={isRunning || backendStatus === 'offline'}
              aria-label="Execute selected scenario"
            >
              <RefreshCw size={15} className={isRunning ? 'spin' : ''} aria-hidden="true" />
              <span>{isRunning ? 'Verifying proof...' : 'Execute selected scenario'}</span>
            </button>

            <button
              className="btn-secondary"
              onClick={() => setModalOpen(true)}
              disabled={!hasRun}
              aria-label="Inspect raw JSON verifier report and proof data"
            >
              <FileCode size={15} aria-hidden="true" />
              <span>Inspect JSON</span>
            </button>
          </div>
        </aside>

        {/* Right Main Column: Verdict, 7 Gates, Stepper, Receipts, ZK, Logs */}
        <section className={`main-column ${isRunning ? 'loading-dim' : ''}`} aria-label="Verification Results">

          {/* 1. Verdict Banner */}
          <div 
            className={`verdict-banner ${
              !hasRun ? 'tone-notrun' : allPassed ? 'tone-pass' : isDenied ? 'tone-denied' : 'tone-fail'
            }`}
            aria-live="polite"
          >
            <div className="verdict-left">
              <div className="verdict-icon-box" aria-hidden="true">
                {!hasRun ? (
                  <Clock size={22} />
                ) : allPassed ? (
                  <CheckCircle2 size={22} />
                ) : isDenied ? (
                  <ShieldAlert size={22} />
                ) : (
                  <AlertTriangle size={22} />
                )}
              </div>

              <div className="verdict-texts">
                <div className="verdict-headline">
                  {!hasRun
                    ? 'Awaiting execution'
                    : allPassed
                    ? 'Incident containment verified'
                    : isDenied
                    ? 'Action blocked by the policy gate (expected)'
                    : 'Verification check failed'}
                </div>
                <div className="verdict-subtext">
                  {!hasRun
                    ? 'Select a scenario on the left and click "Execute selected scenario" to run the pipeline.'
                    : runData?.denialReason
                    ? runData.denialReason
                    : allPassed
                    ? 'All 4 transitions satisfied. Poseidon commitment bound to public Groth16 proof.'
                    : 'Independent verifier failed closed on mismatched evidence or proof signals.'}
                </div>
              </div>
            </div>

            <div className="runid-chip">
              <span className="runid-label">Run ID</span>
              <span className="runid-value">{runData?.runId ? truncateMiddle(runData.runId, 6, 4) : '—'}</span>
              {runData?.runId && (
                <button
                  className="icon-copy-btn"
                  onClick={() => handleCopy(runData.runId, 'runId')}
                  aria-label="Copy Run ID"
                >
                  {copiedKey === 'runId' ? <Check size={12} color="#8F6F2F" /> : <Copy size={12} />}
                </button>
              )}
            </div>
          </div>

          {/* 2. Verification Checks (7 Distinct Gates) */}
          <div className="content-card">
            <div className="card-header-bar">
              <h2 className="section-title">Verification checks</h2>
              <span className="section-hint">7 independent validation barriers</span>
            </div>

            <div className="gates-list" role="list">
              {GATES.map((gate) => {
                const status = report[gate.key] || 'NOT_RUN';
                return (
                  <div key={gate.id} className="gate-row" role="listitem">
                    <div className="gate-left">
                      <span className="gate-index">{gate.id}</span>
                      <div className="gate-texts">
                        <span className="gate-title">{gate.title}</span>
                        <span className="gate-desc">{gate.desc}</span>
                      </div>
                    </div>
                    {renderStatusBadge(status)}
                  </div>
                );
              })}
            </div>
          </div>

          {/* 3. State Machine Stepper */}
          <div className="content-card">
            <div className="card-header-bar">
              <h2 className="section-title">Incident containment state machine</h2>
              <span className="section-hint">Strict transition enforcement (FSM-v1)</span>
            </div>

            <div className="stepper-track" role="group" aria-label="Incident containment progression">
              {FSM_STEPS.map((node, idx) => {
                const maxReached = isDenied ? 0 : receipts.length;
                const isReached = hasRun && !isDenied && idx <= maxReached;
                const isContainedPass = idx === 4 && allPassed;
                const lineActive = hasRun && !isDenied && idx < maxReached;

                // Format label breaking at underscore
                const labelParts = node.codeName.split('_');

                return (
                  <div key={node.id} className="stepper-node-group">
                    <div className="node-circle-wrap">
                      <div className={`node-circle ${isContainedPass ? 'contained-pass' : isReached ? 'reached' : ''}`}>
                        {node.id}
                      </div>
                      {idx < 4 && (
                        <div className={`node-connector-line ${lineActive ? 'active' : ''}`} aria-hidden="true" />
                      )}
                    </div>
                    <div className="node-label">
                      {labelParts.map((part, pIdx) => (
                        <React.Fragment key={pIdx}>
                          {part}
                          {pIdx < labelParts.length - 1 && <br />}
                        </React.Fragment>
                      ))}
                    </div>
                    <div className="node-action">{node.action}</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 4. Signed Execution Receipts */}
          <div className="content-card">
            <div className="card-header-bar">
              <h2 className="section-title">Signed execution receipts</h2>
              <span className="section-hint">{receipts.length} chained entries</span>
            </div>

            {receipts.length === 0 ? (
              <div className="empty-placeholder">
                {!hasRun
                  ? 'No receipts emitted yet. Execute a scenario to inspect signed execution records.'
                  : 'No receipts generated for this run (action blocked prior to execution).'}
              </div>
            ) : (
              <div className="receipts-grid">
                {receipts.map((r, i) => (
                  <div key={i} className="receipt-card">
                    <div className="receipt-header-row">
                      <span className="receipt-step-num">Step {r.sequence}</span>
                      <span className="executed-badge">EXECUTED</span>
                    </div>

                    <div className="receipt-action-name">{r.action_id}</div>

                    <div className="receipt-table">
                      <div className="receipt-row">
                        <span className="receipt-k">Target</span>
                        <span className="receipt-v">{r.target_id}</span>
                      </div>

                      <div className="receipt-row">
                        <span className="receipt-k">Transition</span>
                        <span className="receipt-v">{r.state_before} → {r.state_after}</span>
                      </div>

                      <div className="receipt-row">
                        <span className="receipt-k">Receipt hash</span>
                        <span className="receipt-v" title={r.receipt_hash}>
                          {truncateMiddle(r.receipt_hash, 6, 4)}
                          <button
                            className="icon-copy-btn"
                            onClick={() => handleCopy(r.receipt_hash, `rh-${i}`)}
                            aria-label={`Copy receipt hash step ${r.sequence}`}
                          >
                            {copiedKey === `rh-${i}` ? <Check size={11} color="#166A43" /> : <Copy size={11} />}
                          </button>
                        </span>
                      </div>

                      <div className="receipt-row">
                        <span className="receipt-k">Prev hash</span>
                        <span className="receipt-v" title={r.previous_receipt_hash}>
                          {r.previous_receipt_hash === 'GENESIS' ? 'GENESIS' : truncateMiddle(r.previous_receipt_hash, 5, 4)}
                          {r.previous_receipt_hash !== 'GENESIS' && (
                            <button
                              className="icon-copy-btn"
                              onClick={() => handleCopy(r.previous_receipt_hash, `prh-${i}`)}
                              aria-label={`Copy previous hash step ${r.sequence}`}
                            >
                              {copiedKey === `prh-${i}` ? <Check size={11} color="#166A43" /> : <Copy size={11} />}
                            </button>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 5. ZK Commitment & Proof Section */}
          <div className="content-card">
            <div className="card-header-bar">
              <h2 className="section-title">Zero-knowledge proof & sequence commitment</h2>
              <span className="section-hint">Poseidon(5) over BN128</span>
            </div>

            <div className="zk-cards-split">
              <div className="zk-field-block">
                <span className="zk-field-label">Recomputed Poseidon commitment</span>
                <div className="zk-field-scrollbox">
                  {computedCommitment || (
                    <span style={{ color: 'var(--text-muted)' }}>
                      Not computed (action blocked before commitment generation)
                    </span>
                  )}
                </div>
                <span className="zk-field-note">Calculated by verifier: Poseidon(run_id, a1, a2, a3, a4)</span>
              </div>

              <div className="zk-field-block">
                <span className="zk-field-label">Proof public signal [1]</span>
                <div className="zk-field-scrollbox">
                  {proofData?.publicSignals?.[1] || (
                    <span style={{ color: 'var(--text-muted)' }}>
                      Not available (no proof provided for this scenario)
                    </span>
                  )}
                </div>
                <span className="zk-field-note">Public signal bound inside arithmetic circuit during proving</span>
              </div>
            </div>

            <div className="zk-field-block">
              <span className="zk-field-label">Groth16 curve points (π_A, π_B, π_C)</span>
              <div className="zk-field-scrollbox" style={{ fontSize: '11px', maxHeight: '100px' }}>
                {proofData?.proof?.pi_a ? (
                  `pi_a: [${proofData.proof.pi_a[0]}, ${proofData.proof.pi_a[1]}]\npi_b: [[${proofData.proof.pi_b[0][0]}, ${proofData.proof.pi_b[0][1]}], [${proofData.proof.pi_b[1][0]}, ${proofData.proof.pi_b[1][1]}]]\nprotocol: ${proofData.proof.protocol}`
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>
                    Proof data not generated for this scenario run.
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* 6. Audit Console */}
          <div className="content-card">
            <div className="card-header-bar">
              <h2 className="section-title">Audit console</h2>
              <span className="section-hint">Telemetry from running execution</span>
            </div>

            <div className="audit-box" role="log" aria-label="Runtime telemetry logs">
              {logs.length === 0 ? (
                <div style={{ color: 'var(--text-muted)' }}>
                  Awaiting run execution. Select a scenario to view real-time runtime audit logs.
                </div>
              ) : (
                logs.map((log, idx) => {
                  let tagClass = 'tag-policy';
                  if (log.stage === 'EXECUTOR') tagClass = 'tag-exec';
                  else if (log.stage === 'EVIDENCE') tagClass = 'tag-evidence';
                  else if (log.stage === 'ZK_PROVER' || log.stage === 'VERIFIER') tagClass = 'tag-zk';
                  else if (log.stage === 'ADVERSARY') tagClass = 'tag-adversary';

                  return (
                    <div key={idx} className="audit-entry">
                      <span className="audit-time">[{log.timestamp.split('T')[1].slice(0, 8)}]</span>
                      <span className={`audit-tag ${tagClass}`}>[{log.stage}]</span>
                      <span className="audit-msg">{log.message}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

        </section>
      </main>

      {/* Inspect JSON Modal */}
      {modalOpen && (
        <div 
          className="modal-overlay" 
          onClick={() => setModalOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-title-inspect"
        >
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <h3 id="modal-title-inspect" className="modal-title">Verification evidence bundle</h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  className="btn-secondary"
                  style={{ width: 'auto', padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => {
                    const payload = modalTab === 'report' ? report : modalTab === 'receipts' ? receipts : proofData;
                    handleCopy(JSON.stringify(payload, null, 2), 'modalJson');
                  }}
                  aria-label="Copy JSON payload"
                >
                  {copiedKey === 'modalJson' ? <Check size={13} color="#166A43" /> : <Copy size={13} />}
                  <span>{copiedKey === 'modalJson' ? 'Copied' : 'Copy JSON'}</span>
                </button>

                <button
                  className="icon-copy-btn"
                  onClick={() => setModalOpen(false)}
                  aria-label="Close dialog"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            <div className="modal-tabs" role="tablist">
              <button
                className={`modal-tab-btn ${modalTab === 'report' ? 'active' : ''}`}
                onClick={() => setModalTab('report')}
                role="tab"
                aria-selected={modalTab === 'report'}
              >
                Verification report
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'receipts' ? 'active' : ''}`}
                onClick={() => setModalTab('receipts')}
                role="tab"
                aria-selected={modalTab === 'receipts'}
              >
                Signed receipts ({receipts.length})
              </button>
              <button
                className={`modal-tab-btn ${modalTab === 'proof' ? 'active' : ''}`}
                onClick={() => setModalTab('proof')}
                role="tab"
                aria-selected={modalTab === 'proof'}
              >
                Groth16 proof data
              </button>
            </div>

            <div className="modal-body">
              <pre className="json-codebox">
                {JSON.stringify(
                  modalTab === 'report' ? report : modalTab === 'receipts' ? receipts : proofData,
                  null,
                  2
                )}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* 3-Column Footer */}
      <footer className="site-footer">
        <div className="container-boxed footer-inner">
          <div>VeriRespond MVP · Team Pyrrhic Commit · HackIndia 2026</div>
          <div>
            <a 
              href="https://github.com/HackIndiaXYZ/hackindia-ai-cybertech-hackathon-2026-pyrrhic-commit" 
              target="_blank" 
              rel="noreferrer" 
              className="footer-link"
            >
              Repository
            </a>
            {' · '}
            <span>Synthetic simulation only. No real systems are touched.</span>
          </div>
          <div>Every status on this page comes from the running backend. Nothing is prefilled.</div>
        </div>
      </footer>
    </div>
  );
}
