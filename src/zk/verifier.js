const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { validateReceiptChain } = require('../crypto/evidence');
const { computeSequenceCommitment } = require('./poseidon');

const ROOT_DIR = path.resolve(__dirname, '../..');
const DEFAULT_VKEY_PATH = path.join(ROOT_DIR, 'circuits/artifacts/fsm_v1.vkey.json');
const DEFAULT_MANIFEST_PATH = path.join(ROOT_DIR, 'circuits/artifacts/manifest.json');

/**
 * Compute SHA-256 of file
 */
function getFileHash(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Perform independent end-to-end verification of:
 * 1. Policy & Execution checks (from receipts)
 * 2. Receipt signatures (Ed25519)
 * 3. Hash chain integrity (SHA-256 chain, monotonic sequence, matching run_id)
 * 4. Receipt-to-proof commitment binding (recomputing Poseidon(5) and matching public inputs)
 * 5. ZK Proof validity (Groth16 verification with pinned vkey)
 *
 * @param {object} params
 * @param {Array<object>} params.receipts - The 4 execution receipts
 * @param {object} params.proofData - { proof, publicSignals }
 * @param {string} params.publicKeyPem - Pinned Ed25519 public key
 * @param {object} [params.options] - Optional custom vkey or manifest paths
 * @returns {Promise<object>} Structured verification report
 */
async function verifyResponse({ receipts, proofData, publicKeyPem, options = {} }) {
  const vkeyPath = options.vkeyPath || DEFAULT_VKEY_PATH;
  const manifestPath = options.manifestPath || DEFAULT_MANIFEST_PATH;

  const manifestHash = getFileHash(manifestPath) || 'UNKNOWN_OR_MISSING';

  const result = {
    policy_check: 'NOT_RUN',
    execution_check: 'NOT_RUN',
    receipt_signatures: 'NOT_RUN',
    hash_chain: 'NOT_RUN',
    commitment_binding: 'NOT_RUN',
    proof_generation: 'NOT_RUN',
    zk_verification: 'NOT_RUN',
    run_id: null,
    policy_version: 'fsm-v1',
    circuit_manifest_hash: manifestHash,
    details: {}
  };

  // 1. Check receipts existence
  if (!Array.isArray(receipts) || receipts.length === 0) {
    result.details.error = 'No receipts provided';
    result.policy_check = 'FAIL';
    result.execution_check = 'FAIL';
    result.receipt_signatures = 'FAIL';
    result.hash_chain = 'FAIL';
    result.commitment_binding = 'FAIL';
    return result;
  }

  const runId = receipts[0].run_id;
  result.run_id = runId;

  // 2. Validate policy decisions and execution results within receipts
  let policyOk = true;
  let execOk = true;
  for (const r of receipts) {
    if (r.decision !== 'ALLOW') policyOk = false;
    if (r.result !== 'EXECUTED') execOk = false;
  }
  result.policy_check = policyOk ? 'PASS' : 'FAIL';
  result.execution_check = execOk ? 'PASS' : 'FAIL';

  // 3. Validate receipt signatures and hash chain
  const chainResult = validateReceiptChain(receipts, publicKeyPem, runId);
  if (chainResult.valid) {
    result.receipt_signatures = 'PASS';
    result.hash_chain = 'PASS';
  } else {
    result.receipt_signatures = 'FAIL';
    result.hash_chain = 'FAIL';
    result.details.chain_error = chainResult.error;
    result.commitment_binding = 'FAIL';
    result.zk_verification = 'FAIL';
    return result;
  }

  // 4. Validate proof generation presence
  if (!proofData || !proofData.proof || !proofData.publicSignals) {
    result.proof_generation = 'FAIL';
    result.commitment_binding = 'FAIL';
    result.zk_verification = 'FAIL';
    result.details.proof_error = 'Proof or public signals missing';
    return result;
  }
  result.proof_generation = 'PASS';

  // 5. Receipt-to-Proof Commitment Binding Check
  // Extract canonical action codes and run_id from verified receipts
  const actionCodes = receipts.map(r => r.action_code);
  if (actionCodes.length !== 4) {
    result.commitment_binding = 'FAIL';
    result.details.binding_error = `Expected 4 action codes, got ${actionCodes.length}`;
    return result;
  }

  let recomputedCommitment;
  try {
    recomputedCommitment = await computeSequenceCommitment(runId, actionCodes);
  } catch (err) {
    result.commitment_binding = 'FAIL';
    result.details.binding_error = `Failed to recompute commitment: ${err.message}`;
    return result;
  }

  const publicRunId = proofData.publicSignals[0];
  const publicCommitment = proofData.publicSignals[1];

  const runIdMatches = (publicRunId === runId.toString());
  const commitmentMatches = (publicCommitment === recomputedCommitment);

  if (runIdMatches && commitmentMatches) {
    result.commitment_binding = 'PASS';
  } else {
    result.commitment_binding = 'FAIL';
    result.details.binding_error = {
      runIdMatches,
      commitmentMatches,
      expectedRunId: runId.toString(),
      proofRunId: publicRunId,
      expectedCommitment: recomputedCommitment,
      proofCommitment: publicCommitment
    };
    // Per specification: A proof paired with mismatched public inputs/receipts MUST fail binding
  }

  // 6. Independent ZK Proof Verification with pinned vkey
  if (!fs.existsSync(vkeyPath)) {
    result.zk_verification = 'FAIL';
    result.details.zk_error = `Verification key not found at ${vkeyPath}`;
    return result;
  }

  try {
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    const proofValid = await snarkjs.groth16.verify(
      vkey,
      proofData.publicSignals,
      proofData.proof
    );

    result.zk_verification = proofValid ? 'PASS' : 'FAIL';
    if (!proofValid) {
      result.details.zk_error = 'Groth16 mathematical verification returned false';
    }
  } catch (err) {
    result.zk_verification = 'FAIL';
    result.details.zk_error = `Groth16 verification error: ${err.message}`;
  }

  return result;
}

module.exports = {
  verifyResponse,
  getFileHash,
  DEFAULT_VKEY_PATH,
  DEFAULT_MANIFEST_PATH
};
