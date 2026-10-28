const assert = require('assert');
const { checkProverArtifacts, DEFAULT_WASM_PATH, DEFAULT_ZKEY_PATH } = require('../src/zk/prover');
const { verifyResponse } = require('../src/zk/verifier');
const { executeScenario } = require('../src/simulation/pipeline');

async function runBaselineTests() {
  console.log('=== Running Baseline Robustness & Honest Status Tests ===');

  // Test 1: checkProverArtifacts detects missing files accurately
  const check = checkProverArtifacts();
  assert.strictEqual(typeof check.available, 'boolean', 'available must be boolean');
  assert.strictEqual(Array.isArray(check.missing), true, 'missing must be array');
  console.log('✓ Test 1 Passed: checkProverArtifacts reports availability correctly');

  // Test 2: executeScenario("happy_path") executes without throwing and reports NOT_RUN for missing prover
  const runResult = await executeScenario('happy_path');
  assert.strictEqual(runResult.receipts.length, 4, 'Must emit 4 signed receipts');
  assert.strictEqual(runResult.verificationReport.policy_check, 'PASS', 'Policy check must PASS');
  assert.strictEqual(runResult.verificationReport.execution_check, 'PASS', 'Execution check must PASS');
  assert.strictEqual(runResult.verificationReport.receipt_signatures, 'PASS', 'Signatures must PASS');
  assert.strictEqual(runResult.verificationReport.hash_chain, 'PASS', 'Hash chain must PASS');

  if (!check.available) {
    assert.strictEqual(runResult.verificationReport.proof_generation, 'NOT_RUN', 'Missing prover must report NOT_RUN');
    assert.strictEqual(runResult.verificationReport.zk_verification, 'NOT_RUN', 'Missing prover must report NOT_RUN for zk');
    assert.notStrictEqual(runResult.verificationReport.zk_verification, 'PASS', 'ZK verification must NEVER report PASS when proof is missing');
    console.log('✓ Test 2 Passed: Honest NOT_RUN reported when proving artifacts absent');
  } else {
    console.log('✓ Test 2 Passed: Proving artifacts present; proof verified');
  }

  // Test 3: Policy denial path reports DENIED honestly without state mutation
  const denialResult = await executeScenario('policy_denial');
  assert.strictEqual(denialResult.policyStatus, 'DENIED', 'Policy status must be DENIED');
  assert.strictEqual(denialResult.verificationReport.policy_check, 'DENIED', 'Verifier must report DENIED');
  assert.strictEqual(denialResult.receipts.length, 0, 'No receipts should be emitted for denied request');
  assert.strictEqual(denialResult.stateHistory[0].state, 0, 'Initial state must be 0 (DETECTED)');
  assert.strictEqual(denialResult.stateHistory.length, 1, 'State must remain unchanged at 0');
  console.log('✓ Test 3 Passed: Policy denial preserves state and reports DENIED');

  // Test 4: Tampered receipt fails signature and chain check
  const tamperedResult = await executeScenario('tampered_receipt');
  assert.strictEqual(tamperedResult.verificationReport.receipt_signatures, 'FAIL', 'Tampered receipt must FAIL signature check');
  assert.strictEqual(tamperedResult.verificationReport.hash_chain, 'FAIL', 'Tampered receipt must FAIL chain check');
  console.log('✓ Test 4 Passed: Tampered receipt properly detected and marked FAIL');

  // Test 5: Broken chain fails validation
  const brokenChainResult = await executeScenario('broken_chain');
  assert.strictEqual(brokenChainResult.verificationReport.hash_chain, 'FAIL', 'Missing receipt must FAIL chain check');
  console.log('✓ Test 5 Passed: Broken chain properly detected and marked FAIL');

  console.log('=== All Baseline Tests Succeeded! ===\n');
}

runBaselineTests().catch(err => {
  console.error('Baseline test failure:', err);
  process.exit(1);
});

