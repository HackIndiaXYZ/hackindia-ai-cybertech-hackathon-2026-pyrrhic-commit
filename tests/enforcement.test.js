const assert = require('assert');
const { PolicyGate, ActionEnforcer } = require('../src/enforcement/boundary');
const { generateKeyPair, verifyReceiptSignature } = require('../src/crypto/evidence');

async function runEnforcementTests() {
  console.log('=== Running Action Enforcement Boundary Tests ===');

  const keypair = generateKeyPair();
  const enforcer = new ActionEnforcer({ authorityKeypair: keypair });

  // Track spy calls to verify zero execution on denial
  const spyCalls = { 1: 0, 2: 0, 3: 0, 4: 0 };

  enforcer.registerHandler(1, async (req) => {
    spyCalls[1]++;
    return { blockedIp: req.target_id, timestamp: Date.now() };
  });

  enforcer.registerHandler(2, async (req) => {
    spyCalls[2]++;
    return { rotatedCred: req.target_id, newKeyId: 'key-new-001' };
  });

  enforcer.registerHandler(3, async (req) => {
    spyCalls[3]++;
    return { isolatedService: req.target_id, status: 'ISOLATED' };
  });

  enforcer.registerHandler(4, async (req) => {
    spyCalls[4]++;
    return { confirmed: true, containmentCheck: 'VERIFIED' };
  });

  const runId = 'test-run-enforcement-001';

  // Test 1: Out-of-order action is DENIED and handler is NOT invoked
  console.log('Test 1: Proposing out-of-order action (ROTATE_CREDENTIAL before BLOCK_IP)...');
  const res1 = await enforcer.execute({
    run_id: runId,
    request_id: 'req-001',
    action_id: 'ROTATE_CREDENTIAL',
    action_code: 2,
    target_id: 'CRED-DEMO-01'
  });

  assert.strictEqual(res1.decision, 'DENIED');
  assert.strictEqual(spyCalls[2], 0, 'Handler 2 must NEVER be called when policy denies request');
  assert.strictEqual(enforcer.getRunState(runId), 0, 'State must remain 0 (DETECTED)');
  console.log('✓ Test 1 Passed: Out-of-order request denied with zero handler execution');

  // Test 2: Disallowed target is DENIED and handler is NOT invoked
  console.log('Test 2: Proposing unauthorized target for step 1...');
  const res2 = await enforcer.execute({
    run_id: runId,
    request_id: 'req-002',
    action_id: 'BLOCK_IP',
    action_code: 1,
    target_id: 'UNAUTHORIZED-IP-999'
  });

  assert.strictEqual(res2.decision, 'DENIED');
  assert.strictEqual(spyCalls[1], 0, 'Handler 1 must NEVER be called for unauthorized target');
  assert.strictEqual(enforcer.getRunState(runId), 0, 'State must remain 0');
  console.log('✓ Test 2 Passed: Disallowed target denied with zero handler execution');

  // Test 3: Authorized action 1 succeeds and invokes registered handler
  console.log('Test 3: Proposing valid action 1 (BLOCK_IP on SRC-DEMO-01)...');
  const res3 = await enforcer.execute({
    run_id: runId,
    request_id: 'req-003',
    action_id: 'BLOCK_IP',
    action_code: 1,
    target_id: 'SRC-DEMO-01'
  });

  assert.strictEqual(res3.decision, 'ALLOW');
  assert.strictEqual(res3.status, 'EXECUTED');
  assert.strictEqual(spyCalls[1], 1, 'Handler 1 must be called exactly once');
  assert.strictEqual(enforcer.getRunState(runId), 1, 'State must transition to 1 (IP_BLOCKED)');
  assert.ok(res3.receipt, 'Signed receipt must be emitted');

  const sigCheck = verifyReceiptSignature(res3.receipt, keypair.publicKeyPem);
  assert.strictEqual(sigCheck.valid, true, 'Receipt signature must be valid');
  console.log('✓ Test 3 Passed: Valid action executed, state transitioned, receipt verified');

  // Test 4: Idempotency - Replay of duplicate request_id does not re-invoke handler
  console.log('Test 4: Replaying identical request_id req-003...');
  const res4 = await enforcer.execute({
    run_id: runId,
    request_id: 'req-003',
    action_id: 'BLOCK_IP',
    action_code: 1,
    target_id: 'SRC-DEMO-01'
  });

  assert.strictEqual(res4.isDuplicate, true, 'Duplicate request must be flagged');
  assert.strictEqual(spyCalls[1], 1, 'Handler 1 must NOT be re-executed on duplicate request');
  console.log('✓ Test 4 Passed: Idempotency enforced, duplicate request rejected without execution');

  // Test 5: Full canonical sequence completion through enforcement boundary
  console.log('Test 5: Executing remaining canonical sequence (2, 3, 4)...');
  const resStep2 = await enforcer.execute({
    run_id: runId, request_id: 'req-004', action_code: 2, target_id: 'CRED-DEMO-01'
  });
  assert.strictEqual(resStep2.decision, 'ALLOW');
  assert.strictEqual(enforcer.getRunState(runId), 2);

  const resStep3 = await enforcer.execute({
    run_id: runId, request_id: 'req-005', action_code: 3, target_id: 'SVC-DEMO-01'
  });
  assert.strictEqual(resStep3.decision, 'ALLOW');
  assert.strictEqual(enforcer.getRunState(runId), 3);

  const resStep4 = await enforcer.execute({
    run_id: runId, request_id: 'req-006', action_code: 4, target_id: 'CONTAINMENT-CHECK'
  });
  assert.strictEqual(resStep4.decision, 'ALLOW');
  assert.strictEqual(enforcer.getRunState(runId), 4);
  assert.strictEqual(spyCalls[2], 1);
  assert.strictEqual(spyCalls[3], 1);
  assert.strictEqual(spyCalls[4], 1);
  console.log('✓ Test 5 Passed: Full sequence successfully mediated through enforcement boundary');

  console.log('=== All Action Enforcement Boundary Tests Passed! ===\n');
}

runEnforcementTests().catch(err => {
  console.error('Enforcement test failure:', err);
  process.exit(1);
});
