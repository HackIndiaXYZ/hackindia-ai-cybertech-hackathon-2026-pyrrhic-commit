const assert = require('assert');
const { generateKeyPair, signReceipt } = require('../src/crypto/evidence');
const { generateFsmProof } = require('../src/zk/prover');
const { verifyResponse } = require('../src/zk/verifier');

function createSignedReceiptChain(runId, privateKeyPem) {
  const actions = [
    { seq: 1, id: 'BLOCK_IP', code: 1, target: 'SRC-DEMO-01', before: 0, after: 1 },
    { seq: 2, id: 'ROTATE_CREDENTIAL', code: 2, target: 'CRED-DEMO-01', before: 1, after: 2 },
    { seq: 3, id: 'ISOLATE_SERVICE', code: 3, target: 'SVC-DEMO-01', before: 2, after: 3 },
    { seq: 4, id: 'CONFIRM_CONTAINMENT', code: 4, target: 'CONTAINMENT-CHECK', before: 3, after: 4 }
  ];

  let previousHash = 'GENESIS';
  const receipts = [];

  for (const a of actions) {
    const raw = {
      schema_version: '1',
      run_id: runId,
      incident_id: 'INC-DEMO-001',
      sequence: a.seq,
      request_id: `req-00${a.seq}`,
      action_id: a.id,
      action_code: a.code,
      target_id: a.target,
      state_before: a.before,
      state_after: a.after,
      decision: 'ALLOW',
      result: 'EXECUTED',
      policy_version: 'fsm-v1',
      previous_receipt_hash: previousHash
    };
    const signed = signReceipt(raw, privateKeyPem);
    previousHash = signed.receipt_hash;
    receipts.push(signed);
  }

  return receipts;
}

async function runE2ETests() {
  console.log('=== Running End-to-End Verification & Adversarial Integration Tests ===');

  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  const runId1 = '10000000000000000001';
  const runId2 = '20000000000000000002';

  // Scenario 1: Happy Path
  console.log('\n[Scenario 1] Happy Path: Valid 4-receipt chain + Valid Groth16 Proof');
  const receipts1 = createSignedReceiptChain(runId1, privateKeyPem);
  const proofData1 = await generateFsmProof(runId1, [1, 2, 3, 4]);

  const report1 = await verifyResponse({
    receipts: receipts1,
    proofData: proofData1,
    publicKeyPem
  });

  console.log('Verification Report 1:', JSON.stringify(report1, null, 2));
  assert.strictEqual(report1.policy_check, 'PASS');
  assert.strictEqual(report1.execution_check, 'PASS');
  assert.strictEqual(report1.receipt_signatures, 'PASS');
  assert.strictEqual(report1.hash_chain, 'PASS');
  assert.strictEqual(report1.commitment_binding, 'PASS');
  assert.strictEqual(report1.proof_generation, 'PASS');
  assert.strictEqual(report1.zk_verification, 'PASS');
  assert.strictEqual(report1.run_id, runId1);
  console.log('✓ Scenario 1 Passed: Complete Happy Path independently verified with all PASS');

  // Scenario 2: Tampered Receipt Payload (Adversary modifies target_id or state)
  console.log('\n[Scenario 2] Adversarial: Receipt payload tampered after signing');
  const tamperedReceipts = JSON.parse(JSON.stringify(receipts1));
  tamperedReceipts[1].target_id = 'FORGED-TARGET';
  const report2 = await verifyResponse({
    receipts: tamperedReceipts,
    proofData: proofData1,
    publicKeyPem
  });

  assert.strictEqual(report2.receipt_signatures, 'FAIL');
  assert.strictEqual(report2.hash_chain, 'FAIL');
  assert.strictEqual(report2.commitment_binding, 'FAIL');
  console.log('✓ Scenario 2 Passed: Receipt tampering detected; signatures and chain FAIL');

  // Scenario 3: Missing Receipt in Chain
  console.log('\n[Scenario 3] Adversarial: Missing receipt (step 3 deleted)');
  const incompleteReceipts = [receipts1[0], receipts1[1], receipts1[3]];
  const report3 = await verifyResponse({
    receipts: incompleteReceipts,
    proofData: proofData1,
    publicKeyPem
  });

  assert.strictEqual(report3.hash_chain, 'FAIL');
  assert.strictEqual(report3.commitment_binding, 'FAIL');
  console.log('✓ Scenario 3 Passed: Incomplete receipt sequence detected; hash_chain and binding FAIL');

  // Scenario 4: Cross-Run Replay / Commitment Binding Attack
  // Valid proof from Run 2 presented with valid receipts from Run 1
  console.log('\n[Scenario 4] Adversarial: Cross-run replay attack (Valid proof from Run 2 paired with receipts from Run 1)');
  const proofData2 = await generateFsmProof(runId2, [1, 2, 3, 4]);

  const report4 = await verifyResponse({
    receipts: receipts1, // Run 1
    proofData: proofData2, // Run 2 proof!
    publicKeyPem
  });

  console.log('Replay report binding result:', report4.commitment_binding, 'ZK result:', report4.zk_verification);
  assert.strictEqual(report4.receipt_signatures, 'PASS');
  assert.strictEqual(report4.hash_chain, 'PASS');
  assert.strictEqual(report4.commitment_binding, 'FAIL', 'Commitment binding must fail for mismatched run/receipts');
  assert.strictEqual(report4.zk_verification, 'PASS', 'Proof itself verifies mathematically but binding check fails');
  console.log('✓ Scenario 4 Passed: Replay attack thwarted by independent commitment binding!');

  // Scenario 5: Tampered Public Input on Proof
  console.log('\n[Scenario 5] Adversarial: Tampered public commitment in proof data');
  const tamperedProofData = {
    proof: proofData1.proof,
    publicSignals: [proofData1.publicSignals[0], '999999999999999999999999']
  };
  const report5 = await verifyResponse({
    receipts: receipts1,
    proofData: tamperedProofData,
    publicKeyPem
  });

  assert.strictEqual(report5.commitment_binding, 'FAIL');
  assert.strictEqual(report5.zk_verification, 'FAIL');
  console.log('✓ Scenario 5 Passed: Tampered proof input rejected by both binding and ZK verifier');

  console.log('\n=== All End-to-End Verification & Adversarial Tests Succeeded! ===\n');
  process.exit(0);
}

runE2ETests().catch(err => {
  console.error('E2E Test Failure:', err);
  process.exit(1);
});
