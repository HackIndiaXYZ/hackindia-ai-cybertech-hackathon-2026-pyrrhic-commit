const assert = require('assert');
const { ActionEnforcer } = require('../src/enforcement/boundary');
const { generateKeyPair, signReceipt, validateReceiptChain } = require('../src/crypto/evidence');
const { verifyResponse } = require('../src/zk/verifier');

async function runSecurityRegressionTests() {
  console.log('=== Running Security Hardening Regression Suite ===');

  const keypair = generateKeyPair();

  // Test 1: Concurrent duplicate requests serialization & single execution
  console.log('Test 1: Concurrent duplicate requests (race condition protection)...');
  let execCount = 0;
  const enforcer = new ActionEnforcer({ authorityKeypair: keypair });
  enforcer.registerHandler(1, async () => {
    execCount++;
    await new Promise(r => setTimeout(r, 40));
    return { ok: true };
  });

  const runId1 = `sec-race-${Date.now()}`;
  const reqId1 = `req-race-${Date.now()}`;

  const [resA, resB] = await Promise.all([
    enforcer.execute({ run_id: runId1, request_id: reqId1, action_code: 1, target_id: 'SRC-DEMO-01' }),
    enforcer.execute({ run_id: runId1, request_id: reqId1, action_code: 1, target_id: 'SRC-DEMO-01' })
  ]);

  assert.strictEqual(execCount, 1, 'Handler must execute exactly ONCE under concurrent duplicate flood');
  const hasDuplicateFlag = resA.isDuplicate || resB.isDuplicate;
  assert.strictEqual(hasDuplicateFlag, true, 'At least one concurrent request must be identified as duplicate');
  console.log('✓ Test 1 Passed: Race condition eliminated; concurrent duplicate safely handled');

  // Test 2: Rejection of unexpected / injected parameters (Parameter Pollution)
  console.log('Test 2: Parameter pollution rejection...');
  const pollRes = await enforcer.execute({
    run_id: runId1,
    request_id: `req-poll-${Date.now()}`,
    action_code: 1,
    target_id: 'SRC-DEMO-01',
    unauthorized_injected_param: 'rm -rf /'
  });
  assert.strictEqual(pollRes.decision, 'DENIED', 'Request with unknown parameter must be denied');
  assert.ok(pollRes.reason.includes('Unexpected or unauthorized request parameter'));
  console.log('✓ Test 2 Passed: Parameter pollution rejected by strict schema validation');

  // Test 3: Truncated / Incomplete Chain Rejection in Verifier
  console.log('Test 3: Truncated chain rejection in independent verifier...');
  const runId3 = `sec-trunc-${Date.now()}`;
  const r1 = signReceipt({
    schema_version: '1', run_id: runId3, incident_id: 'INC-SEC-01', sequence: 1, request_id: 'req1',
    action_id: 'BLOCK_IP', action_code: 1, target_id: 'SRC-DEMO-01', state_before: 0, state_after: 1,
    decision: 'ALLOW', result: 'EXECUTED', policy_version: 'fsm-v1', previous_receipt_hash: 'GENESIS'
  }, keypair.privateKeyPem);

  const truncVerify = await verifyResponse({
    receipts: [r1],
    proofData: null,
    publicKeyPem: keypair.publicKeyPem
  });

  assert.strictEqual(truncVerify.hash_chain, 'FAIL', 'Partial 1-step chain must fail completeness check in verifier');
  assert.ok(truncVerify.details.chain_error.includes('Incomplete receipt chain'));
  console.log('✓ Test 3 Passed: Truncated / incomplete chain rejected');

  console.log('=== All Security Hardening Regression Tests Passed! ===\n');
}

runSecurityRegressionTests().catch(err => {
  console.error('Security regression test failure:', err);
  process.exit(1);
});
