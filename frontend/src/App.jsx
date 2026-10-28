import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Cpu, 
  Terminal, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  RefreshCw, 
  FileCode, 
  Check, 
  Copy, 
  Layers, 
  Hash, 
  Activity,
  ArrowRight,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import './App.css';

const SCENARIOS = [
  {
    id: 'happy_path',
    name: '1. Happy Path (Valid 4-Step Containment)',
    desc: 'Sequence 1→2→3→4 satisfies FSM. Ed25519 signatures, hash chain, Poseidon commitment & Groth16 proof all verify.',
    color: '#10b981',
    badge: 'VALID'
  },
  {
    id: 'policy_denial',
    name: '2. Policy Gate Denial',
    desc: 'Adversary requests out-of-order action ISOLATE_SERVICE from state 0. Blocked before execution without state mutation.',
    color: '#f59e0b',
    badge: 'SECURITY'
  },
  {
    id: 'tampered_receipt',
    name: '3. Tampered Receipt Payload',
    desc: 'Adversary modifies target_id in signed receipt. Independent Ed25519 signature & SHA-256 chain verification fail.',
    color: '#ef4444',
    badge: 'ADVERSARIAL'
  },
  {
    id: 'broken_chain',
    name: '4. Broken Hash Chain',
    desc: 'Receipt #3 omitted from sequence. SHA-256 backward linkage and commitment binding checks fail closed.',
    color: '#ef4444',
    badge: 'ADVERSARIAL'
  },
  {
    id: 'replay_attack',
    name: '5. Cross-Run Replay Attack',
    desc: 'Valid Groth16 proof from foreign run presented with current receipts. Commitment binding check detects mismatch.',
    color: '#8b5cf6',
    badge: 'ATTACK'
  },
  {
    id: 'tampered_proof',
    name: '6. Tampered Proof Signal',
    desc: 'Public Poseidon commitment altered inside proof. Independent pairing check and binding both reject the proof.',
    color: '#ef4444',
    badge: 'CRYPTO FAULT'
  }
];

export default function App() {
  const [systemMeta, setSystemMeta] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('happy_path');
  const [isRunning, setIsRunning] = useState(false);
  const [runData, setRunData] = useState(null);
  const [error, setError] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTab, setModalTab] = useState('report');
  const [copied, setCopied] = useState(false);

  // Fetch initial system status & pinned hashes
  useEffect(() => {
    fetch('/api/status')
      .then(res => res.json())
      .then(data => {
        setSystemMeta(data);
        // Automatically run happy path on initial launch to populate dashboard
        triggerScenario('happy_path');
      })
      .catch(err => {
        console.error('Failed to connect to API server:', err);
        setError('Could not connect to VeriRespond backend server. Ensure node src/server.js is running.');
      });
  }, []);

  const triggerScenario = async (scenarioId) => {
    setIsRunning(true);
    setError(null);
    setSelectedScenario(scenarioId);

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setRunData(data);
    } catch (err) {
      setError(err.message || 'Execution failed');
    } finally {
      setIsRunning(false);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return <span className="status-badge badge-pass">PASS</span>;
      case 'FAIL':
        return <span className="status-badge badge-fail">FAIL</span>;
      case 'DENIED':
        return <span className="status-badge badge-denied">DENIED</span>;
      default:
        return <span className="status-badge badge-not-run">NOT_RUN</span>;
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'PASS':
        return <CheckCircle size={16} color="#34d399" />;
      case 'FAIL':
        return <XCircle size={16} color="#f87171" />;
      case 'DENIED':
        return <ShieldAlert size={16} color="#fbbf24" />;
      default:
        return <Activity size={16} color="#94a3b8" />;
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const report = runData?.verificationReport || {};
  const receipts = runData?.receipts || [];
  const proofData = runData?.proofData || null;
  const logs = runData?.logs || [];

  // Determine overall run verdict honestly (never hardcoded)
  const isHappyPath = runData?.scenario === 'happy_path';
  const allPassed = 
    report.policy_check === 'PASS' &&
    report.execution_check === 'PASS' &&
    report.receipt_signatures === 'PASS' &&
    report.hash_chain === 'PASS' &&
    report.commitment_binding === 'PASS' &&
    report.zk_verification === 'PASS';

  const isDenied = report.policy_check === 'DENIED';

  return (
    <div className="app-wrapper">
      {/* Top Navbar */}
      <header className="top-navbar">
        <div className="brand-section">
          <div className="brand-shield">
            <Shield size={24} />
          </div>
          <div>
            <div className="brand-title">
              VERIRESPOND
              <span className="fsm-tag">FSM-V1</span>
            </div>
            <div className="brand-sub">Evidence-Grounded, Policy-Constrained AI Incident Response MVP</div>
          </div>
        </div>

        <div className="header-telemetry">
          <div className="telemetry-item">
            <span className="telemetry-label">CIRCUIT MANIFEST SHA-256</span>
            <span className="telemetry-value mono">
              {systemMeta?.circuit_manifest_hash ? `${systemMeta.circuit_manifest_hash.slice(0, 16)}...` : 'Computing...'}
            </span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">VERIFIER VKEY SHA-256</span>
            <span className="telemetry-value mono">
              {systemMeta?.verification_key_hash ? `${systemMeta.verification_key_hash.slice(0, 16)}...` : 'Computing...'}
            </span>
          </div>
          <div className="system-pill">
            <span className="status-dot-active"></span>
            <span>ZK ENGINE READY</span>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="main-dashboard">
        
        {/* Left Column: Scenarios & 7 Verification Gates */}
        <section className="panel">
          <div className="panel-title-bar">
            <h2>
              <Layers size={18} color="var(--accent-cyan)" />
              Simulation & Attack Scenarios
            </h2>
            <span className="sub-title">Select Scenario</span>
          </div>

          <div className="scenarios-grid">
            {SCENARIOS.map(sc => (
              <button
                key={sc.id}
                className={`scenario-card ${selectedScenario === sc.id ? 'active' : ''}`}
                onClick={() => triggerScenario(sc.id)}
                disabled={isRunning}
              >
                <div className="scenario-icon">
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: sc.color }} />
                </div>
                <div>
                  <div className="scenario-name">{sc.name}</div>
                  <div className="scenario-desc">{sc.desc}</div>
                </div>
              </button>
            ))}
          </div>

          <div className="action-controls">
            <button 
              className="btn-primary" 
              onClick={() => triggerScenario(selectedScenario)}
              disabled={isRunning}
            >
              <RefreshCw size={16} className={isRunning ? 'spin' : ''} />
              {isRunning ? 'Proving & Verifying...' : 'Execute Selected Scenario'}
            </button>
            <button className="btn-secondary" onClick={() => setModalOpen(true)}>
              <FileCode size={16} />
              Inspect JSON
            </button>
          </div>

          {/* 7 Verification Gates */}
          <div className="panel-title-bar" style={{ marginTop: '0.5rem' }}>
            <h2>
              <ShieldCheck size={18} color="var(--accent-emerald)" />
              7 Independent Verification Gates
            </h2>
            <span className="sub-title">Per-Spec Statuses</span>
          </div>

          <div className="gates-container">
            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.policy_check)}
                  1. POLICY GATE
                </div>
                <div className="gate-subtitle">Runtime FSM transition & authorized target</div>
              </div>
              {getStatusBadge(report.policy_check)}
            </div>

            <div className="gate-card gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.execution_check)}
                  2. SIMULATED EXECUTION
                </div>
                <div className="gate-subtitle">Safe mock environment state mutation</div>
              </div>
              {getStatusBadge(report.execution_check)}
            </div>

            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.receipt_signatures)}
                  3. RECEIPT SIGNATURES
                </div>
                <div className="gate-subtitle">Ed25519 signature verified for each receipt</div>
              </div>
              {getStatusBadge(report.receipt_signatures)}
            </div>

            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.hash_chain)}
                  4. HASH CHAIN INTEGRITY
                </div>
                <div className="gate-subtitle">SHA-256 backward chain links & monotonic sequence</div>
              </div>
              {getStatusBadge(report.hash_chain)}
            </div>

            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.commitment_binding)}
                  5. COMMITMENT BINDING
                </div>
                <div className="gate-subtitle">Poseidon(5) over receipts matches proof input</div>
              </div>
              {getStatusBadge(report.commitment_binding)}
            </div>

            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.proof_generation)}
                  6. ZK PROOF GENERATION
                </div>
                <div className="gate-subtitle">Groth16 prover execution on Circom fsm_v1</div>
              </div>
              {getStatusBadge(report.proof_generation)}
            </div>

            <div className="gate-item">
              <div>
                <div className="gate-title">
                  {getStatusIcon(report.zk_verification)}
                  7. INDEPENDENT ZK VERIFICATION
                </div>
                <div className="gate-subtitle">Snarkjs pairing check against pinned verification key</div>
              </div>
              {getStatusBadge(report.zk_verification)}
            </div>
          </div>
        </section>

        {/* Right Column: Execution Outcome, FSM Timeline, Receipts, ZK & Logs */}
        <section className="panel">
          
          {/* Outcome Banner */}
          <div className="outcome-banner">
            <div className="banner-content">
              <div 
                className="banner-icon-box"
                style={{ 
                  background: allPassed ? 'rgba(16, 185, 129, 0.2)' : isDenied ? 'rgba(245, 158, 11, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                  color: allPassed ? '#34d399' : isDenied ? '#fbbf24' : '#f87171'
                }}
              >
                {allPassed ? <CheckCircle size={22} /> : isDenied ? <ShieldAlert size={22} /> : <AlertTriangle size={22} />}
              </div>
              <div>
                <div className="banner-headline">
                  {isRunning 
                    ? 'Executing Groth16 Prover & Verification...' 
                    : allPassed 
                    ? 'Incident Successfully Contained & Cryptographically Verified' 
                    : isDenied 
                    ? 'Adversarial Action Blocked by Deterministic Policy Gate'
                    : 'Adversarial Attack / Cryptographic Fault Detected & Rejected'}
                </div>
                <div className="banner-desc">
                  {runData?.denialReason 
                    ? runData.denialReason 
                    : isHappyPath 
                    ? 'All 4 FSM transitions satisfied. Poseidon commitment bound to public Groth16 proof.' 
                    : 'Independent verifier failed closed on mismatched evidence or proof signals.'}
                </div>
              </div>
            </div>

            <div className="telemetry-item">
              <span className="telemetry-label">RUN ID</span>
              <span className="telemetry-value mono">{runData?.runId || '—'}</span>
            </div>
          </div>

          {/* FSM State Stepper */}
          <div className="panel-title-bar">
            <h2>
              <Activity size={18} color="var(--accent-cyan)" />
              Incident Containment State Machine (FSM-v1)
            </h2>
            <span className="sub-title">Deterministic Transitions</span>
          </div>

          <div className="fsm-stepper-wrap">
            {[
              { id: 0, name: 'DETECTED', action: 'INIT' },
              { id: 1, name: 'IP_BLOCKED', action: 'BLOCK_IP' },
              { id: 2, name: 'REVOKED', action: 'ROTATE_CRED' },
              { id: 3, name: 'ISOLATED', action: 'ISOLATE_SVC' },
              { id: 4, name: 'CONTAINED', action: 'CONFIRM' },
            ].map((node, idx) => {
              const maxReached = isDenied ? 0 : receipts.length;
              const isCompleted = idx <= maxReached && !isDenied;
              const isCurrent = idx === maxReached;
              
              return (
                <React.Fragment key={node.id}>
                  <div className="fsm-node">
                    <div className={`node-number ${isCompleted ? 'completed' : isCurrent ? 'active' : ''}`}>
                      {node.id}
                    </div>
                    <div className="node-name">{node.name}</div>
                    <div className="node-action">{node.action}</div>
                  </div>
                  {idx < 4 && (
                    <div className={`fsm-connector ${idx < maxReached && !isDenied ? 'active' : ''}`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>

          {/* Cryptographic Receipts Chain */}
          <div className="panel-title-bar">
            <h2>
              <Hash size={18} color="var(--accent-cyan)" />
              Signed Execution Receipts & SHA-256 Chain
            </h2>
            <span className="sub-title">{receipts.length} Emitted Receipts</span>
          </div>

          {receipts.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
              No receipts generated for this run (execution blocked before receipt emission).
            </div>
          ) : (
            <div className="receipts-list">
              {receipts.map((r, i) => (
                <div key={i} className="receipt-card" onClick={() => { setModalTab('receipts'); setModalOpen(true); }}>
                  <div className="receipt-top">
                    <span className="receipt-seq">Step #{r.sequence}: {r.action_id}</span>
                    <span className="mono" style={{ color: 'var(--accent-emerald)', fontSize: '0.7rem' }}>EXECUTED</span>
                  </div>
                  <div className="receipt-field">
                    <span className="field-k">Target:</span>
                    <span className="field-v mono">{r.target_id}</span>
                  </div>
                  <div className="receipt-field">
                    <span className="field-k">FSM State:</span>
                    <span className="field-v mono">{r.state_before} → {r.state_after}</span>
                  </div>
                  <div className="receipt-field">
                    <span className="field-k">Receipt Hash:</span>
                    <span className="field-v mono">{r.receipt_hash.slice(0, 14)}...</span>
                  </div>
                  <div className="receipt-field">
                    <span className="field-k">Prev Hash:</span>
                    <span className="field-v mono">{r.previous_receipt_hash === 'GENESIS' ? 'GENESIS' : `${r.previous_receipt_hash.slice(0, 10)}...`}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ZK Prover & Commitment Inspector */}
          <div className="panel-title-bar">
            <h2>
              <Cpu size={18} color="var(--accent-purple)" />
              Zero-Knowledge Commitment & Groth16 Prover
            </h2>
            <span className="sub-title">Curve BN128</span>
          </div>

          <div className="zk-box">
            <div className="zk-unit">
              <span className="zk-title">RECOMPUTED POSEIDON(5) COMMITMENT</span>
              <span className="zk-hash mono">
                {report.details?.computed_commitment || 'Not computed'}
              </span>
              <span className="zk-subtext">Computed by independent verifier: Poseidon(run_id, a1, a2, a3, a4)</span>
            </div>

            <div className="zk-unit">
              <span className="zk-title">PROOF PUBLIC SIGNAL [1]</span>
              <span className="zk-hash mono">
                {proofData?.publicSignals?.[1] || 'Not provided'}
              </span>
              <span className="zk-subtext">Public input bound inside arithmetic circuit during proving</span>
            </div>

            <div className="zk-unit" style={{ gridColumn: '1 / -1' }}>
              <span className="zk-title">GROTH16 CURVE POINTS (π_A, π_B, π_C)</span>
              <span className="zk-hash mono" style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                {proofData?.proof?.pi_a 
                  ? `pi_a: [${proofData.proof.pi_a[0].slice(0, 16)}..., ${proofData.proof.pi_a[1].slice(0, 16)}...] | protocol: ${proofData.proof.protocol}` 
                  : 'Proof not generated for this scenario.'}
              </span>
            </div>
          </div>

          {/* Terminal Console */}
          <div className="panel-title-bar">
            <h2>
              <Terminal size={18} color="var(--accent-cyan)" />
              Live Audit & Execution Console
            </h2>
            <span className="sub-title">Runtime Telemetry</span>
          </div>

          <div className="terminal-console">
            {logs.length === 0 ? (
              <div className="log-entry">
                <span className="log-text">No logs available yet.</span>
              </div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="log-entry">
                  <span className="log-time mono">[{log.timestamp.split('T')[1].slice(0, 8)}]</span>
                  <span className="log-stage mono">[{log.stage}]</span>
                  <span className={`log-text ${log.level === 'warn' ? 'log-warn' : log.level === 'error' ? 'log-error' : ''}`}>
                    {log.message}
                  </span>
                </div>
              ))
            )}
          </div>

        </section>
      </main>

      {/* Raw Data Modal */}
      {modalOpen && (
        <div className="modal-backdrop" onClick={() => setModalOpen(false)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                <FileCode size={18} color="var(--accent-cyan)" />
                Cryptographic Artifact & Verifier Inspector
              </div>
              <button 
                className="btn-secondary" 
                style={{ padding: '0.3rem 0.6rem' }} 
                onClick={() => copyToClipboard(JSON.stringify(
                  modalTab === 'report' ? report : modalTab === 'receipts' ? receipts : proofData, null, 2
                ))}
              >
                {copied ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy JSON'}
              </button>
            </div>

            <div className="modal-tabs">
              <button 
                className={`tab-btn ${modalTab === 'report' ? 'active' : ''}`}
                onClick={() => setModalTab('report')}
              >
                Verification Report
              </button>
              <button 
                className={`tab-btn ${modalTab === 'receipts' ? 'active' : ''}`}
                onClick={() => setModalTab('receipts')}
              >
                Signed Receipts ({receipts.length})
              </button>
              <button 
                className={`tab-btn ${modalTab === 'proof' ? 'active' : ''}`}
                onClick={() => setModalTab('proof')}
              >
                Groth16 Proof Data
              </button>
            </div>

            <div className="modal-body">
              <pre className="json-pre">
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

      {/* Footer */}
      <footer className="app-footer">
        <div>VeriRespond MVP — Team Pyrrhic Commit (HackIndia 2026)</div>
        <div>All 7 verification gates run dynamically; no outputs or proofs are fabricated.</div>
      </footer>
    </div>
  );
}
