/**
 * Reference AI Agent demonstrating tool execution mediated by VeriRespond SDK.
 * 
 * Flow:
 * 1. Checks connector health.
 * 2. Proposes allowed action 1 (BLOCK_IP on SRC-DEMO-01) -> SUCCEEDS.
 * 3. Proposes illegal action (out of order or wrong target) -> DENIED without execution.
 * 4. Completes remaining sequence (ROTATE_CREDENTIAL, ISOLATE_SERVICE, CONFIRM_CONTAINMENT).
 */

const { VeriRespondClient } = require('../packages/sdk/src/index');

async function runReferenceAgent(baseUrl = 'http://localhost:3000') {
  console.log('=== Starting VeriRespond Reference AI Agent ===');
  const client = new VeriRespondClient({ baseUrl });

  const health = await client.getHealth();
  console.log(`[Agent] Connected to VeriRespond Policy Gateway (status: ${health.status})`);

  const runId = `agent-run-${Date.now()}`;
  console.log(`[Agent] Initiating incident response for Run ID: ${runId}`);

  // Step 1: Propose valid action 1
  console.log('[Agent] Action proposal 1: BLOCK_IP on SRC-DEMO-01...');
  const res1 = await client.execute({
    run_id: runId,
    request_id: `${runId}-req-1`,
    action_code: 1,
    action_id: 'BLOCK_IP',
    target_id: 'SRC-DEMO-01'
  });
  console.log(`[Agent] Gate Decision: ${res1.decision} (Status: ${res1.status})`);
  if (res1.receipt) {
    console.log(`[Agent] Signed Receipt Emitted: [SHA256: ${res1.receipt.receipt_hash.slice(0, 16)}...]`);
  }

  // Step 2 (Adversarial test): Agent attempts unauthorized target
  console.log('[Agent] Action proposal 2 (Adversarial): BLOCK_IP on unauthorized target ATTACKER-IP...');
  const resAdversarial = await client.execute({
    run_id: runId,
    request_id: `${runId}-req-adv`,
    action_code: 1,
    action_id: 'BLOCK_IP',
    target_id: 'ATTACKER-IP'
  });
  console.log(`[Agent] Gate Decision: ${resAdversarial.decision} - Reason: ${resAdversarial.reason}`);

  // Step 3: Propose valid action 2
  console.log('[Agent] Action proposal 3: ROTATE_CREDENTIAL on CRED-DEMO-01...');
  const res2 = await client.execute({
    run_id: runId,
    request_id: `${runId}-req-2`,
    action_code: 2,
    action_id: 'ROTATE_CREDENTIAL',
    target_id: 'CRED-DEMO-01'
  });
  console.log(`[Agent] Gate Decision: ${res2.decision} (Status: ${res2.status})`);

  // Step 4: Propose valid action 3
  console.log('[Agent] Action proposal 4: ISOLATE_SERVICE on SVC-DEMO-01...');
  const res3 = await client.execute({
    run_id: runId,
    request_id: `${runId}-req-3`,
    action_code: 3,
    action_id: 'ISOLATE_SERVICE',
    target_id: 'SVC-DEMO-01'
  });
  console.log(`[Agent] Gate Decision: ${res3.decision} (Status: ${res3.status})`);

  // Step 5: Propose valid action 4
  console.log('[Agent] Action proposal 5: CONFIRM_CONTAINMENT on CONTAINMENT-CHECK...');
  const res4 = await client.execute({
    run_id: runId,
    request_id: `${runId}-req-4`,
    action_code: 4,
    action_id: 'CONFIRM_CONTAINMENT',
    target_id: 'CONTAINMENT-CHECK'
  });
  console.log(`[Agent] Gate Decision: ${res4.decision} (Status: ${res4.status})`);
  console.log('=== Reference AI Agent Response Completed Successfully! ===');
  return { res1, resAdversarial, res2, res3, res4 };
}

if (require.main === module) {
  runReferenceAgent().catch(err => {
    console.error('Agent failed:', err);
    process.exit(1);
  });
}

module.exports = { runReferenceAgent };
