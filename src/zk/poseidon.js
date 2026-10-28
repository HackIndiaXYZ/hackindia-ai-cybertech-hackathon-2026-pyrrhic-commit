const { buildPoseidon } = require('circomlibjs');

let poseidonInstance = null;

/**
 * Lazy-load and cache the Poseidon hasher
 */
async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Compute the Poseidon(5) sequence commitment over:
 * [run_id, action_code_1, action_code_2, action_code_3, action_code_4]
 * 
 * @param {string|BigInt} runId - Decimal string representation of field element
 * @param {Array<number|string|BigInt>} actionCodes - Array of 4 action codes
 * @returns {Promise<string>} Decimal string of the Poseidon commitment
 */
async function computeSequenceCommitment(runId, actionCodes) {
  if (!Array.isArray(actionCodes) || actionCodes.length !== 4) {
    throw new Error('Action codes must be an array of exactly 4 elements');
  }

  const poseidon = await getPoseidon();
  const F = poseidon.F;

  const inputs = [
    BigInt(runId.toString()),
    BigInt(actionCodes[0]),
    BigInt(actionCodes[1]),
    BigInt(actionCodes[2]),
    BigInt(actionCodes[3])
  ];

  const hash = poseidon(inputs);
  return F.toString(hash);
}

module.exports = {
  getPoseidon,
  computeSequenceCommitment
};
