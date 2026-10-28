const assert = require('assert');
const fs = require('fs');
const snarkjs = require('snarkjs');
const { computeSequenceCommitment } = require('../src/zk/poseidon');
const { generateFsmProof, DEFAULT_WASM_PATH, DEFAULT_ZKEY_PATH } = require('../src/zk/prover');
const { DEFAULT_VKEY_PATH } = require('../src/zk/verifier');

async function runZkTests() {
  console.log('=== Running ZK Circuit & Prover Unit Tests ===');

  const runId = '12345678901234567890';
  const canonicalActions = [1, 2, 3, 4];
  const vkey = JSON.parse(fs.readFileSync(DEFAULT_VKEY_PATH, 'utf8'));

  // Test 1: Valid canonical sequence proof generation and verification
  console.log('Test 1: Generating valid proof for canonical sequence [1, 2, 3, 4]...');
  const proofResult = await generateFsmProof(runId, canonicalActions);
  assert.strictEqual(proofResult.publicSignals[0], runId, 'Public signal 0 must be run_id');
  const expectedCommitment = await computeSequenceCommitment(runId, canonicalActions);
  assert.strictEqual(proofResult.publicSignals[1], expectedCommitment, 'Public signal 1 must match computed Poseidon commitment');

  const isValid = await snarkjs.groth16.verify(vkey, proofResult.publicSignals, proofResult.proof);
  assert.strictEqual(isValid, true, 'Valid proof must verify successfully with pinned vkey');
  console.log('✓ Test 1 Passed: Valid Groth16 proof generated and verified');

  // Test 2: Invalid sequence [1, 3, 2, 4] must fail constraint check
  console.log('Test 2: Attempting to prove invalid sequence [1, 3, 2, 4] (must fail constraints)...');
  let invalidWitnessFailed = false;
  try {
    await generateFsmProof(runId, [1, 3, 2, 4]);
  } catch (err) {
    invalidWitnessFailed = true;
    console.log(`✓ Test 2 Passed: Prover rejected invalid transition: ${err.message}`);
  }
  assert.strictEqual(invalidWitnessFailed, true, 'Prover must fail constraint satisfaction for invalid sequence');

  // Test 3: Tampered public signals (different commitment) must fail verification
  console.log('Test 3: Verifying with tampered public signals...');
  const tamperedPublic = [proofResult.publicSignals[0], '999999999999999999999999999999999999999999'];
  const tamperedPublicResult = await snarkjs.groth16.verify(vkey, tamperedPublic, proofResult.proof);
  assert.strictEqual(tamperedPublicResult, false, 'Tampered public input must fail verification');
  console.log('✓ Test 3 Passed: Tampered public inputs fail verification');

  // Test 4: Tampered proof bytes must fail verification
  console.log('Test 4: Verifying with tampered proof structure...');
  const tamperedProof = JSON.parse(JSON.stringify(proofResult.proof));
  tamperedProof.pi_a[0] = '123456789';
  const tamperedProofResult = await snarkjs.groth16.verify(vkey, proofResult.publicSignals, tamperedProof);
  assert.strictEqual(tamperedProofResult, false, 'Tampered proof points must fail verification');
  console.log('✓ Test 4 Passed: Tampered proof points fail verification');

  console.log('=== All ZK Circuit & Prover Unit Tests Passed! ===\n');
  process.exit(0);
}

runZkTests().catch(err => {
  console.error('ZK Test failure:', err);
  process.exit(1);
});
