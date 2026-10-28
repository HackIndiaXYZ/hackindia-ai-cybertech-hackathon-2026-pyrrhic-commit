/**
 * VeriRespond Server & Cryptographic Engine Entrypoint
 * Re-exports the HTTP server/handler for Vercel/Node and preserves cryptographic library helpers.
 */

const server = require('./src/server.js');
const { canonicalize } = require('./src/crypto/canonical');
const {
  DOMAIN_SEPARATOR,
  generateKeyPair,
  computeReceiptHash,
  signReceipt,
  verifyReceiptSignature,
  validateReceiptChain
} = require('./src/crypto/evidence');
const { getPoseidon, computeSequenceCommitment } = require('./src/zk/poseidon');
const { generateFsmProof, DEFAULT_WASM_PATH, DEFAULT_ZKEY_PATH } = require('./src/zk/prover');
const { verifyResponse, getFileHash, DEFAULT_VKEY_PATH, DEFAULT_MANIFEST_PATH } = require('./src/zk/verifier');

// Attach helpers to server handler
server.canonicalize = canonicalize;
server.DOMAIN_SEPARATOR = DOMAIN_SEPARATOR;
server.generateKeyPair = generateKeyPair;
server.computeReceiptHash = computeReceiptHash;
server.signReceipt = signReceipt;
server.verifyReceiptSignature = verifyReceiptSignature;
server.validateReceiptChain = validateReceiptChain;
server.getPoseidon = getPoseidon;
server.computeSequenceCommitment = computeSequenceCommitment;
server.generateFsmProof = generateFsmProof;
server.DEFAULT_WASM_PATH = DEFAULT_WASM_PATH;
server.DEFAULT_ZKEY_PATH = DEFAULT_ZKEY_PATH;
server.verifyResponse = verifyResponse;
server.getFileHash = getFileHash;
server.DEFAULT_VKEY_PATH = DEFAULT_VKEY_PATH;
server.DEFAULT_MANIFEST_PATH = DEFAULT_MANIFEST_PATH;

module.exports = server;
