const crypto = require('crypto');
const { canonicalize } = require('./canonical');

const DOMAIN_SEPARATOR = 'VERIRESPOND-RECEIPT-V1\n';

/**
 * Generate Ed25519 keypair for demonstration
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}

/**
 * Extract payload for SHA-256 receipt_hash computation.
 * Excludes `receipt_hash` and `signature`.
 */
function getHashPayload(receipt) {
  const payload = { ...receipt };
  delete payload.receipt_hash;
  delete payload.signature;
  return payload;
}

/**
 * Compute SHA-256 hash of canonical receipt payload (excluding receipt_hash and signature).
 */
function computeReceiptHash(receipt) {
  const payload = getHashPayload(receipt);
  const canon = canonicalize(payload);
  return crypto.createHash('sha256').update(canon, 'utf8').digest('hex');
}

/**
 * Extract payload for Ed25519 signature computation.
 * Includes `receipt_hash` but excludes `signature`.
 */
function getSignPayload(receipt) {
  const payload = { ...receipt };
  delete payload.signature;
  return payload;
}

/**
 * Compute domain-separated signable bytes for receipt.
 */
function getSignableBytes(receipt) {
  const payload = getSignPayload(receipt);
  const canon = canonicalize(payload);
  return Buffer.concat([
    Buffer.from(DOMAIN_SEPARATOR, 'utf8'),
    Buffer.from(canon, 'utf8')
  ]);
}

/**
 * Sign receipt with Ed25519 private key.
 * Modifies or returns new receipt with receipt_hash and signature.
 */
function signReceipt(receiptData, privateKeyPem, signingKeyId = 'demo-ed25519-v1') {
  const receipt = { ...receiptData };
  receipt.signing_key_id = signingKeyId;

  // 1. Compute receipt_hash
  receipt.receipt_hash = computeReceiptHash(receipt);

  // 2. Compute signature over domain-separated payload including receipt_hash
  const signable = getSignableBytes(receipt);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signatureBuf = crypto.sign(null, signable, privateKey);

  receipt.signature = signatureBuf.toString('base64');
  return receipt;
}

/**
 * Verify a single receipt signature and internal receipt_hash integrity.
 */
function verifyReceiptSignature(receipt, publicKeyPem) {
  if (!receipt || !receipt.receipt_hash || !receipt.signature) {
    return { valid: false, error: 'Missing receipt_hash or signature' };
  }

  // 1. Verify receipt_hash integrity
  const expectedHash = computeReceiptHash(receipt);
  if (receipt.receipt_hash !== expectedHash) {
    return {
      valid: false,
      error: `Receipt hash mismatch: expected ${expectedHash}, got ${receipt.receipt_hash}`
    };
  }

  // 2. Verify Ed25519 signature
  try {
    const signable = getSignableBytes(receipt);
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const signatureBuf = Buffer.from(receipt.signature, 'base64');
    const valid = crypto.verify(null, signable, publicKey, signatureBuf);
    if (!valid) {
      return { valid: false, error: 'Ed25519 signature verification failed' };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: `Signature verification error: ${err.message}` };
  }
}

/**
 * Validate an ordered array of receipts for:
 * 1. Monotonic sequence numbering 1..N
 * 2. Consistent run_id across all receipts
 * 3. First previous_receipt_hash === 'GENESIS'
 * 4. Chained previous_receipt_hash === preceding receipt_hash
 * 5. Signatures and individual hashes valid against publicKeyPem
 */
function validateReceiptChain(receipts, publicKeyPem, expectedRunId = null) {
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return { valid: false, error: 'Receipts must be a non-empty array' };
  }

  let previousHash = 'GENESIS';
  const targetRunId = expectedRunId || receipts[0].run_id;

  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const expectedSeq = i + 1;

    if (r.sequence !== expectedSeq) {
      return {
        valid: false,
        error: `Sequence mismatch at index ${i}: expected ${expectedSeq}, got ${r.sequence}`
      };
    }

    if (r.run_id !== targetRunId) {
      return {
        valid: false,
        error: `Run ID mismatch at index ${i}: expected ${targetRunId}, got ${r.run_id}`
      };
    }

    if (r.previous_receipt_hash !== previousHash) {
      return {
        valid: false,
        error: `Hash chain broken at index ${i}: expected previous_hash ${previousHash}, got ${r.previous_receipt_hash}`
      };
    }

    const sigResult = verifyReceiptSignature(r, publicKeyPem);
    if (!sigResult.valid) {
      return {
        valid: false,
        error: `Receipt ${r.sequence} failed verification: ${sigResult.error}`
      };
    }

    previousHash = r.receipt_hash;
  }

  return { valid: true, count: receipts.length, run_id: targetRunId };
}

module.exports = {
  DOMAIN_SEPARATOR,
  generateKeyPair,
  canonicalize,
  computeReceiptHash,
  signReceipt,
  verifyReceiptSignature,
  validateReceiptChain
};
