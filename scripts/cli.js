#!/usr/bin/env node

/**
 * VeriRespond Crypto & ZK CLI Tool
 * Command-line interface for signing, proving, commitment calculation, and independent verification.
 */

const fs = require('fs');
const path = require('path');
const { generateKeyPair, signReceipt, verifyReceiptSignature, validateReceiptChain } = require('../src/crypto/evidence');
const { computeSequenceCommitment } = require('../src/zk/poseidon');
const { generateFsmProof } = require('../src/zk/prover');
const { verifyResponse } = require('../src/zk/verifier');

function printUsage() {
  console.log(`
Usage: node scripts/cli.js <command> [options]

Commands:
  gen-keys                           Generate an Ed25519 keypair
  commitment <run_id> [actions_json] Compute Poseidon(5) sequence commitment
  prove <run_id> [actions_json]      Generate Groth16 proof for 4-action sequence
  verify <receipts_json> <proof_json> <public_key_pem_file>
                                     Run independent end-to-end verification
`);
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (!cmd) {
    printUsage();
    process.exit(1);
  }

  switch (cmd) {
    case 'gen-keys': {
      const keys = generateKeyPair();
      console.log(JSON.stringify(keys, null, 2));
      break;
    }

    case 'commitment': {
      const runId = args[1];
      if (!runId) {
        console.error('Error: missing run_id');
        process.exit(1);
      }
      const actions = args[2] ? JSON.parse(args[2]) : [1, 2, 3, 4];
      const comm = await computeSequenceCommitment(runId, actions);
      console.log(JSON.stringify({ run_id: runId, commitment: comm }));
      break;
    }

    case 'prove': {
      const runId = args[1];
      if (!runId) {
        console.error('Error: missing run_id');
        process.exit(1);
      }
      const actions = args[2] ? JSON.parse(args[2]) : [1, 2, 3, 4];
      const proofResult = await generateFsmProof(runId, actions);
      console.log(JSON.stringify(proofResult, null, 2));
      break;
    }

    case 'verify': {
      const receiptsPath = args[1];
      const proofPath = args[2];
      const pubKeyPath = args[3];

      if (!receiptsPath || !proofPath || !pubKeyPath) {
        console.error('Error: Missing arguments for verify command');
        process.exit(1);
      }

      const receipts = JSON.parse(fs.readFileSync(receiptsPath, 'utf8'));
      const proofData = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
      const publicKeyPem = fs.readFileSync(pubKeyPath, 'utf8');

      const report = await verifyResponse({
        receipts,
        proofData,
        publicKeyPem
      });

      console.log(JSON.stringify(report, null, 2));
      break;
    }

    default:
      console.error(`Unknown command: ${cmd}`);
      printUsage();
      process.exit(1);
  }
}

main().catch(err => {
  console.error('CLI Error:', err.message);
  process.exit(1);
});
