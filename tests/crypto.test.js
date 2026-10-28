const assert = require('assert');
const {
  generateKeyPair,
  signReceipt,
  verifyReceiptSignature,
  validateReceiptChain
} = require('../src/crypto/evidence');

console.log('--- Running Cryptographic Evidence & Hash Chain Tests ---');

const { publicKeyPem, privateKeyPem } = generateKeyPair();
const runId = '98765432101234567890';

// Build sample 4-receipt chain
function buildSampleChain() {
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

// Test 1: Valid chain passes
const validChain = buildSampleChain();
const validResult = validateReceiptChain(validChain, publicKeyPem, runId);
assert.strictEqual(validResult.valid, true, 'Valid chain should validate successfully');
console.log('✓ Test 1: Valid chain passed');

// Test 2: Tampered receipt payload fails signature/hash verification
const tamperedReceipt = { ...validChain[0], target_id: 'SRC-ATTACK-99' };
const singleVerifyResult = verifyReceiptSignature(tamperedReceipt, publicKeyPem);
assert.strictEqual(singleVerifyResult.valid, false, 'Tampered target_id must fail signature/hash verification');
console.log('✓ Test 2: Tampered receipt payload rejected');

// Test 3: Tampered signature fails
const badSigReceipt = { ...validChain[1], signature: validChain[0].signature };
const badSigResult = verifyReceiptSignature(badSigReceipt, publicKeyPem);
assert.strictEqual(badSigResult.valid, false, 'Swapped signature must fail verification');
console.log('✓ Test 3: Invalid signature rejected');

// Test 4: Reordered receipts fail chain verification
const reorderedChain = [validChain[1], validChain[0], validChain[2], validChain[3]];
const reorderResult = validateReceiptChain(reorderedChain, publicKeyPem, runId);
assert.strictEqual(reorderResult.valid, false, 'Reordered receipts must fail validation');
console.log('✓ Test 4: Reordered receipts rejected');

// Test 5: Missing receipt (gap) fails chain verification
const missingChain = [validChain[0], validChain[2], validChain[3]];
const missingResult = validateReceiptChain(missingChain, publicKeyPem, runId);
assert.strictEqual(missingResult.valid, false, 'Chain with missing receipt must fail');
console.log('✓ Test 5: Missing receipt in chain rejected');

// Test 6: Mismatched run ID fails
const wrongRunIdResult = validateReceiptChain(validChain, publicKeyPem, '11111111111111111111');
assert.strictEqual(wrongRunIdResult.valid, false, 'Mismatched run ID must fail');
console.log('✓ Test 6: Mismatched run ID rejected');

// Test 7: Tampered intermediate hash fails chain verification
const tamperedChain = buildSampleChain();
tamperedChain[1].previous_receipt_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const brokenChainResult = validateReceiptChain(tamperedChain, publicKeyPem, runId);
assert.strictEqual(brokenChainResult.valid, false, 'Tampered previous_receipt_hash must fail chain check');
console.log('✓ Test 7: Broken hash link rejected');

console.log('--- All Cryptographic Evidence Tests Passed Successfully! ---');
