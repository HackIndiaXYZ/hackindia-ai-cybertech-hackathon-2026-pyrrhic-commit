/**
 * VeriRespond — Cryptographic Evidence & ZK Proof Engine
 * Team: Pyrrhic Commit (HackIndia 2026)
 */

const { canonicalize } = require('./src/crypto/canonical');
const {
  DOMAIN_SEPARATOR,
  generateKeyPair,
  computeReceiptHash,
  signReceipt,
  verifyReceiptSignature,
  validateReceiptChain
} = require('./src/crypto/evidence');

const {
  getPoseidon,
  computeSequenceCommitment
} = require('./src/zk/poseidon');

const {
  generateFsmProof,
  DEFAULT_WASM_PATH,
  DEFAULT_ZKEY_PATH
} = require('./src/zk/prover');

const {
  verifyResponse,
  getFileHash,
  DEFAULT_VKEY_PATH,
  DEFAULT_MANIFEST_PATH
} = require('./src/zk/verifier');

module.exports = {
  // Canonical serialization
  canonicalize,

  // Ed25519 & SHA-256 evidence
  DOMAIN_SEPARATOR,
  generateKeyPair,
  computeReceiptHash,
  signReceipt,
  verifyReceiptSignature,
  validateReceiptChain,

  // Poseidon commitment
  getPoseidon,
  computeSequenceCommitment,

  // Groth16 prover
  generateFsmProof,
  DEFAULT_WASM_PATH,
  DEFAULT_ZKEY_PATH,

  // Independent verifier
  verifyResponse,
  getFileHash,
  DEFAULT_VKEY_PATH,
  DEFAULT_MANIFEST_PATH
};
