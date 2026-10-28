const assert = require('assert');
const path = require('path');
const server = require(path.resolve(__dirname, '../../../src/server'));
const { VeriRespondClient } = require('../src/index');

async function testSdk() {
  console.log('=== Running VeriRespond SDK Unit & Integration Tests ===');

  const PORT = 3003;
  await new Promise(resolve => server.listen(PORT, resolve));

  try {
    const client = new VeriRespondClient({ baseUrl: `http://localhost:${PORT}` });

    // Test 1: getHealth()
    const health = await client.getHealth();
    assert.strictEqual(health.status, 'UP');
    console.log('✓ Test 1: getHealth() returned UP');

    // Test 2: getSpecs()
    const specs = await client.getSpecs();
    assert.strictEqual(specs.policy_version, 'fsm-v1');
    console.log('✓ Test 2: getSpecs() returned fsm-v1');

    // Test 3: execute allowed action
    const runId = `sdk-test-${Date.now()}`;
    const allowRes = await client.execute({
      run_id: runId,
      request_id: `${runId}-req-1`,
      action_code: 1,
      target_id: 'SRC-DEMO-01'
    });
    assert.strictEqual(allowRes.success, true);
    assert.strictEqual(allowRes.decision, 'ALLOW');
    assert.ok(allowRes.receipt);
    console.log('✓ Test 3: execute() allowed action and returned signed receipt');

    // Test 4: execute denied action
    const denyRes = await client.execute({
      run_id: runId,
      request_id: `${runId}-req-2`,
      action_code: 1,
      target_id: 'UNAUTHORIZED-IP'
    });
    assert.strictEqual(denyRes.success, false);
    assert.strictEqual(denyRes.decision, 'DENIED');
    console.log('✓ Test 4: execute() denied unauthorized action correctly');

    console.log('=== All SDK Tests Succeeded! ===\n');
  } finally {
    server.close();
  }
}

testSdk().catch(err => {
  console.error('SDK Test failure:', err);
  process.exit(1);
});
