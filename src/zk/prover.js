const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { computeSequenceCommitment } = require('./poseidon');

const ROOT_DIR = path.resolve(__dirname, '../..');
const DEFAULT_WASM_PATH = path.join(ROOT_DIR, 'circuits/build/fsm_v1_js/fsm_v1.wasm');
const DEFAULT_ZKEY_PATH = path.join(ROOT_DIR, 'circuits/artifacts/fsm_v1_final.zkey');

const DEFAULT_PREPARED_PATH = path.join(ROOT_DIR, 'circuits/artifacts/prepared_proof.json');

/**
 * Generate a ZK Groth16 proof for the VeriRespond FSM v1 sequence.
 * 
 * @param {string|BigInt} runId - Run identifier field element (as decimal string)
 * @param {Array<number>} actionCodes - Array of 4 action codes [1, 2, 3, 4]
 * @param {object} [paths] - Optional custom wasm and zkey paths
 * @returns {Promise<{proof: object, publicSignals: string[], commitment: string, artifact_type: string}>}
 */
async function generateFsmProof(runId, actionCodes, paths = {}) {
  if (!Array.isArray(actionCodes) || actionCodes.length !== 4) {
    throw new Error('Action codes must contain exactly 4 numbers');
  }

  const wasmPath = paths.wasmPath || DEFAULT_WASM_PATH;
  const zkeyPath = paths.zkeyPath || DEFAULT_ZKEY_PATH;
  const preparedPath = paths.preparedPath || DEFAULT_PREPARED_PATH;

  // Fallback to PREPARED ARTIFACT if WASM or ZKEY binaries are not present in deployment
  if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
    if (fs.existsSync(preparedPath)) {
      const prepared = JSON.parse(fs.readFileSync(preparedPath, 'utf8'));
      return {
        proof: prepared.proof,
        publicSignals: prepared.publicSignals,
        commitment: prepared.commitment,
        run_id: prepared.run_id,
        artifact_type: 'PREPARED ARTIFACT',
        notice: 'Groth16 circuit binaries not present in serverless container; using pre-generated proof verified against pinned verification key.'
      };
    }
    throw new Error(`WASM file not found at ${wasmPath} and no prepared artifact found. Run setup first.`);
  }

  // 1. Compute expected Poseidon commitment
  const commitment = await computeSequenceCommitment(runId, actionCodes);

  // 2. Prepare circuit inputs
  const circuitInputs = {
    run_id: runId.toString(),
    sequence_commitment: commitment,
    action_code_1: actionCodes[0].toString(),
    action_code_2: actionCodes[1].toString(),
    action_code_3: actionCodes[2].toString(),
    action_code_4: actionCodes[3].toString()
  };

  // 3. Generate Groth16 witness and proof
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    wasmPath,
    zkeyPath
  );

  return {
    proof,
    publicSignals,
    commitment,
    run_id: runId.toString(),
    artifact_type: 'LIVE GENERATED'
  };
}

module.exports = {
  generateFsmProof,
  DEFAULT_WASM_PATH,
  DEFAULT_ZKEY_PATH
};
