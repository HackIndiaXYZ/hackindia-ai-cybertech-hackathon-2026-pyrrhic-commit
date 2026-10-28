/**
 * VeriRespond Incident Simulation & Scenario Pipeline
 * 
 * Implements the mock incident lifecycle, FSM policy gate,
 * evidence receipt generation, Poseidon commitment, and ZK verification.
 * 
 * Non-negotiable security invariant:
 * - Signing keys are never exposed to planner or frontend presentation.
 * - Presentation layer consumes only raw verifier reports.
 */

const fs = require('fs');
const { generateKeyPair, signReceipt } = require('../crypto/evidence');
const { computeSequenceCommitment } = require('../zk/poseidon');
const { generateFsmProof, DEFAULT_WASM_PATH } = require('../zk/prover');
const { verifyResponse, getFileHash, DEFAULT_MANIFEST_PATH } = require('../zk/verifier');

// Frozen FSM transitions according to PROTOCOL_AND_CONTRACTS.md
const FSM_TRANSITIONS = {
  1: { id: 'BLOCK_IP', name: 'Block Malicious IP', from: 0, to: 1, allowedTargets: ['SRC-DEMO-01', 'SRC-DEMO-02'] },
  2: { id: 'ROTATE_CREDENTIAL', name: 'Rotate Compromised Credential', from: 1, to: 2, allowedTargets: ['CRED-DEMO-01', 'CRED-DEMO-02'] },
  3: { id: 'ISOLATE_SERVICE', name: 'Isolate Impacted Service', from: 2, to: 3, allowedTargets: ['SVC-DEMO-01', 'SVC-DEMO-02'] },
  4: { id: 'CONFIRM_CONTAINMENT', name: 'Confirm System Containment', from: 3, to: 4, allowedTargets: ['CONTAINMENT-CHECK'] }
};

const STATE_NAMES = {
  0: 'DETECTED',
  1: 'IP_BLOCKED',
  2: 'CREDENTIAL_ROTATED',
  3: 'SERVICE_ISOLATED',
  4: 'CONTAINED'
};

// Internal keypair for the mock evidence authority
let mockAuthorityKeypair = null;

function getAuthorityKeypair() {
  if (!mockAuthorityKeypair) {
    if (process.env.SIGNING_KEY) {
      try {
        const crypto = require('crypto');
        const privateKeyPem = process.env.SIGNING_KEY.replace(/\\n/g, '\n');
        const pub = crypto.createPublicKey(privateKeyPem);
        const publicKeyPem = pub.export({ type: 'spki', format: 'pem' });
        mockAuthorityKeypair = { privateKeyPem, publicKeyPem };
      } catch (e) {
        console.warn('Warning: Failed to parse SIGNING_KEY from env, generating fallback keypair:', e.message);
        mockAuthorityKeypair = generateKeyPair();
      }
    } else {
      mockAuthorityKeypair = generateKeyPair();
    }
  }
  return mockAuthorityKeypair;
}

/**
 * Policy Gate Check
 */
function evaluatePolicyGate(currentState, actionCode, targetId) {
  const transition = FSM_TRANSITIONS[actionCode];
  if (!transition) {
    return {
      decision: 'DENIED',
      reason: `Unknown action code: ${actionCode}`
    };
  }

  if (currentState !== transition.from) {
    return {
      decision: 'DENIED',
      reason: `Invalid state transition: Action ${transition.id} requires state ${STATE_NAMES[transition.from]} (${transition.from}), but current state is ${STATE_NAMES[currentState]} (${currentState})`
    };
  }

  if (!transition.allowedTargets.includes(targetId)) {
    return {
      decision: 'DENIED',
      reason: `Target ${targetId} is not authorized for action ${transition.id}`
    };
  }

  return {
    decision: 'ALLOW',
    transition
  };
}

/**
 * Execute a complete scenario and return the live telemetry + verifier results
 * 
 * @param {string} scenarioType - 'happy_path' | 'policy_denial' | 'tampered_receipt' | 'broken_chain' | 'replay_attack' | 'tampered_proof'
 * @param {object} customParams - optional overrides
 */
async function executeScenario(scenarioType = 'happy_path', customParams = {}) {
  const keys = getAuthorityKeypair();
  const isBinaryPresent = fs.existsSync(DEFAULT_WASM_PATH);
  const runId = customParams.runId || (isBinaryPresent ? `${Date.now()}` : '10000000000000000001');
  const incidentId = 'INC-DEMO-001';

  const logs = [];
  function log(stage, message, level = 'info') {
    logs.push({
      timestamp: new Date().toISOString(),
      stage,
      message,
      level
    });
  }

  log('INIT', `Starting scenario execution: ${scenarioType.toUpperCase()} (Run ID: ${runId})`);

  let currentState = 0;
  let previousHash = 'GENESIS';
  const receipts = [];
  const actionExecutionLog = [];

  // Scenario 2: Policy Denial Path
  if (scenarioType === 'policy_denial') {
    log('PLANNER', 'Planner proposes out-of-order action: ISOLATE_SERVICE directly from DETECTED state');
    
    // Attempting action 3 (ISOLATE_SERVICE) from state 0
    const gateEval = evaluatePolicyGate(currentState, 3, 'SVC-DEMO-01');
    log('POLICY_GATE', `Policy gate evaluated request: ${gateEval.decision} - ${gateEval.reason}`, 'warn');

    return {
      runId,
      scenario: scenarioType,
      policyStatus: 'DENIED',
      denialReason: gateEval.reason,
      receipts: [],
      proofData: null,
      verificationReport: {
        policy_check: 'DENIED',
        execution_check: 'NOT_RUN',
        receipt_signatures: 'NOT_RUN',
        hash_chain: 'NOT_RUN',
        commitment_binding: 'NOT_RUN',
        proof_generation: 'NOT_RUN',
        zk_verification: 'NOT_RUN',
        run_id: runId,
        policy_version: 'fsm-v1',
        circuit_manifest_hash: getFileHash(DEFAULT_MANIFEST_PATH) || 'UNKNOWN',
        details: { policy_denial: gateEval.reason }
      },
      logs,
      stateHistory: [{ state: 0, name: 'DETECTED', action: null }]
    };
  }

  // Standard 4-step sequence execution
  const plannedSteps = [
    { code: 1, target: 'SRC-DEMO-01' },
    { code: 2, target: 'CRED-DEMO-01' },
    { code: 3, target: 'SVC-DEMO-01' },
    { code: 4, target: 'CONTAINMENT-CHECK' }
  ];

  const stateHistory = [{ state: 0, name: 'DETECTED', action: 'INITIAL_STATE' }];

  for (let i = 0; i < plannedSteps.length; i++) {
    const step = plannedSteps[i];
    const seq = i + 1;

    // 1. Policy Gate Check
    const gateEval = evaluatePolicyGate(currentState, step.code, step.target);
    if (gateEval.decision !== 'ALLOW') {
      log('POLICY_GATE', `Action ${step.code} rejected: ${gateEval.reason}`, 'error');
      break;
    }
    log('POLICY_GATE', `Policy gate APPROVED action ${gateEval.transition.id} (Step ${seq}/4)`);

    // 2. Simulated Execution
    const stateBefore = currentState;
    const stateAfter = gateEval.transition.to;
    currentState = stateAfter;
    log('EXECUTOR', `Simulated state mutated: ${STATE_NAMES[stateBefore]} (${stateBefore}) -> ${STATE_NAMES[stateAfter]} (${stateAfter}) on target ${step.target}`);
    stateHistory.push({ state: stateAfter, name: STATE_NAMES[stateAfter], action: gateEval.transition.id });

    // 3. Evidence Receipt Emission & Signature
    const rawReceipt = {
      schema_version: '1',
      run_id: runId,
      incident_id: incidentId,
      sequence: seq,
      request_id: `req-${String(seq).padStart(3, '0')}`,
      action_id: gateEval.transition.id,
      action_code: step.code,
      target_id: step.target,
      state_before: stateBefore,
      state_after: stateAfter,
      decision: 'ALLOW',
      result: 'EXECUTED',
      policy_version: 'fsm-v1',
      previous_receipt_hash: previousHash
    };

    const signedReceipt = signReceipt(rawReceipt, keys.privateKeyPem);
    previousHash = signedReceipt.receipt_hash;
    receipts.push(signedReceipt);

    log('EVIDENCE', `Emitted signed receipt seq #${seq} [SHA256: ${signedReceipt.receipt_hash.slice(0, 16)}...]`);
  }

  // 4. Cryptographic Proof Generation
  log('ZK_PROVER', `Computing Poseidon(5) sequence commitment for run ${runId}...`);
  const commitment = await computeSequenceCommitment(runId, [1, 2, 3, 4]);
  log('ZK_PROVER', `Poseidon commitment: ${commitment.slice(0, 16)}...`);

  log('ZK_PROVER', 'Generating Groth16 zero-knowledge proof using circuits/artifacts/fsm_v1.zkey...');
  const proofStartTime = Date.now();
  let proofData = await generateFsmProof(runId, [1, 2, 3, 4]);
  const proofDuration = Date.now() - proofStartTime;
  log('ZK_PROVER', `Groth16 proof generated in ${proofDuration}ms. Public signals: [${proofData.publicSignals.join(', ')}]`);

  // Handle Adversarial Scenarios
  let receiptsForVerification = JSON.parse(JSON.stringify(receipts));
  let proofForVerification = JSON.parse(JSON.stringify(proofData));

  if (scenarioType === 'tampered_receipt') {
    log('ADVERSARY', 'Injecting tamper fault: modifying target_id of receipt #2 after signature emission', 'warn');
    receiptsForVerification[1].target_id = 'ATTACKER_TARGET_99';
  } else if (scenarioType === 'broken_chain') {
    log('ADVERSARY', 'Injecting chain fault: omitting receipt #3 (ISOLATE_SERVICE)', 'warn');
    receiptsForVerification = [receiptsForVerification[0], receiptsForVerification[1], receiptsForVerification[3]];
  } else if (scenarioType === 'replay_attack') {
    const foreignRunId = '99999999999999999999';
    log('ADVERSARY', `Injecting replay attack: generating valid proof for foreign run ${foreignRunId} and presenting with current receipts`, 'warn');
    proofForVerification = await generateFsmProof(foreignRunId, [1, 2, 3, 4]);
  } else if (scenarioType === 'tampered_proof') {
    log('ADVERSARY', 'Injecting proof fault: altering public input commitment signal', 'warn');
    proofForVerification.publicSignals[1] = '123456789012345678901234567890';
  }

  // 5. Independent Verification
  log('VERIFIER', 'Running independent verifier across all 5 verification gates...');
  const verificationReport = await verifyResponse({
    receipts: receiptsForVerification,
    proofData: proofForVerification,
    publicKeyPem: keys.publicKeyPem
  });

  log('VERIFIER', `Verification complete. Final status: ZK=${verificationReport.zk_verification}, Signatures=${verificationReport.receipt_signatures}, Chain=${verificationReport.hash_chain}, Commitment=${verificationReport.commitment_binding}`);

  return {
    runId,
    scenario: scenarioType,
    publicKeyPem: keys.publicKeyPem,
    receipts: receiptsForVerification,
    proofData: proofForVerification,
    verificationReport,
    logs,
    stateHistory,
    executionTimeMs: proofDuration
  };
}

module.exports = {
  FSM_TRANSITIONS,
  STATE_NAMES,
  getAuthorityKeypair,
  evaluatePolicyGate,
  executeScenario
};
