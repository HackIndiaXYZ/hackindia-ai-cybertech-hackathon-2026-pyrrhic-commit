const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { DurableStore } = require('../src/storage/store');
const { ActionEnforcer } = require('../src/enforcement/boundary');
const { generateKeyPair, validateReceiptChain } = require('../src/crypto/evidence');

async function runStorageTests() {
  console.log('=== Running Durable Storage & Restart Recovery Tests ===');

  const testDir = path.resolve(__dirname, '../data_test_' + Date.now());
  const store = new DurableStore(testDir);
  const keypair = generateKeyPair();

  const runId = 'durable-run-001';

  // Test 1: Save and recover run
  store.saveRun(runId, { state: 0, incident_id: 'INC-STORAGE-01' });
  const recovered = store.getRun(runId);
  assert.strictEqual(recovered.state, 0, 'Recovered run state must match');
  console.log('✓ Test 1 Passed: Run state saved and recovered from disk');

  // Test 2: Process execution and recover in fresh enforcer instance (simulating restart)
  const enforcer1 = new ActionEnforcer({ store, authorityKeypair: keypair });
  enforcer1.registerHandler(1, async () => ({ action: 'BLOCK_IP' }));
  enforcer1.registerHandler(2, async () => ({ action: 'ROTATE_CREDENTIAL' }));

  const res1 = await enforcer1.execute({
    run_id: runId, request_id: 'req-dur-1', action_code: 1, target_id: 'SRC-DEMO-01'
  });
  assert.strictEqual(res1.status, 'EXECUTED');

  // Simulate total process restart with brand new ActionEnforcer reading from same store
  console.log('Simulating server restart...');
  const enforcer2 = new ActionEnforcer({ store, authorityKeypair: keypair });
  enforcer2.registerHandler(2, async () => ({ action: 'ROTATE_CREDENTIAL' }));

  // Check state recovery
  const recoveredState = enforcer2.getRunState(runId);
  assert.strictEqual(recoveredState, 1, 'New enforcer instance must recover state 1 (IP_BLOCKED)');
  console.log('✓ Test 2 Passed: Process restart cleanly recovered run state from durable store');

  // Test 3: Idempotency after restart
  const dupAfterRestart = await enforcer2.execute({
    run_id: runId, request_id: 'req-dur-1', action_code: 1, target_id: 'SRC-DEMO-01'
  });
  assert.strictEqual(dupAfterRestart.isDuplicate, true, 'Request must be detected as duplicate even across restart');
  console.log('✓ Test 3 Passed: Idempotency persisted and enforced across process restarts');

  // Test 4: Hash chain continuity across restart
  const res2 = await enforcer2.execute({
    run_id: runId, request_id: 'req-dur-2', action_code: 2, target_id: 'CRED-DEMO-01'
  });
  assert.strictEqual(res2.status, 'EXECUTED');

  const receipts = store.getReceipts(runId);
  assert.strictEqual(receipts.length, 2, '2 receipts must be persisted in store');
  const chainCheck = validateReceiptChain(receipts, keypair.publicKeyPem, runId);
  assert.strictEqual(chainCheck.valid, true, 'Hash chain across restarts must be cryptographically valid');
  console.log('✓ Test 4 Passed: Hash chain verified valid across restarted execution');

  // Cleanup test directory
  fs.rmSync(testDir, { recursive: true, force: true });
  console.log('=== All Storage & Recovery Tests Passed! ===\n');
}

runStorageTests().catch(err => {
  console.error('Storage test failure:', err);
  process.exit(1);
});
