/**
 * VeriRespond Web Server & API Layer
 * 
 * Serves the responsive frontend dashboard and exposes verification & scenario simulation APIs.
 * Uses native Node.js HTTP/fs/path modules for zero external web framework overhead.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const { ActionEnforcer, PolicyGate } = require('./enforcement/boundary');
const { FSM_TRANSITIONS, STATE_NAMES } = require('./enforcement/constants');
const { executeScenario, getAuthorityKeypair } = require('./simulation/pipeline');
const { verifyResponse, getFileHash, DEFAULT_MANIFEST_PATH, DEFAULT_VKEY_PATH } = require('./zk/verifier');

// Global action enforcer instance with standard handlers registered
const globalEnforcer = new ActionEnforcer({
  policyGate: new PolicyGate({ policyVersion: 'fsm-v1', transitions: FSM_TRANSITIONS }),
  authorityKeypair: getAuthorityKeypair()
});

// Register standard simulated tool handlers
globalEnforcer.registerHandler(1, async (req) => {
  return { action: 'BLOCK_IP', target: req.target_id, timestamp: Date.now(), rule: 'DROP' };
});
globalEnforcer.registerHandler(2, async (req) => {
  return { action: 'ROTATE_CREDENTIAL', target: req.target_id, timestamp: Date.now(), status: 'ROTATED' };
});
globalEnforcer.registerHandler(3, async (req) => {
  return { action: 'ISOLATE_SERVICE', target: req.target_id, timestamp: Date.now(), networkState: 'QUARANTINED' };
});
globalEnforcer.registerHandler(4, async (req) => {
  return { action: 'CONFIRM_CONTAINMENT', target: req.target_id, timestamp: Date.now(), confirmed: true };
});

const PORT = process.env.PORT || 3000;
const FRONTEND_DIST = path.resolve(__dirname, '../frontend/dist');
const FALLBACK_PUBLIC = path.resolve(__dirname, '../public');

// Choose frontend/dist if available
const STATIC_DIR = fs.existsSync(path.join(FRONTEND_DIST, 'index.html'))
  ? FRONTEND_DIST
  : FALLBACK_PUBLIC;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png'
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data, null, 2));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) { // 5MB limit
        reject(new Error('Request payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // --- API Endpoints ---
  if ((pathname === '/api/status' || pathname === '/api/specs') && req.method === 'GET') {
    const manifestHash = getFileHash(DEFAULT_MANIFEST_PATH);
    const vkeyHash = getFileHash(DEFAULT_VKEY_PATH);
    const authorityKeys = getAuthorityKeypair();

    return sendJson(res, 200, {
      status: 'OPERATIONAL',
      policy_version: 'fsm-v1',
      circuit_manifest_hash: manifestHash || 'UNKNOWN',
      verification_key_hash: vkeyHash || 'UNKNOWN',
      public_key_pem: authorityKeys.publicKeyPem,
      fsm_transitions: FSM_TRANSITIONS,
      state_names: STATE_NAMES,
      supported_scenarios: [
        { id: 'happy_path', name: 'Happy Path (Valid 4-Step Sequence)', desc: 'Valid containment sequence with passing ZK Groth16 proof & verified chain.' },
        { id: 'policy_denial', name: 'Policy Gate Denial', desc: 'Out-of-order action rejected by policy before execution; prevents illegal state mutation.' },
        { id: 'tampered_receipt', name: 'Tampered Receipt Payload', desc: 'Attacker modifies signed receipt target; signature & hash chain fail.' },
        { id: 'broken_chain', name: 'Broken Hash Chain', desc: 'Receipt omitted from sequence; hash chain linkage & commitment binding fail.' },
        { id: 'replay_attack', name: 'Cross-Run Replay Attack', desc: 'Valid proof from another run paired with current receipts; binding verification fails.' },
        { id: 'tampered_proof', name: 'Tampered Proof Public Input', desc: 'Public signal tampered; rejected by both binding and ZK snarkjs verifier.' }
      ]
    });
  }

  if (pathname === '/api/health' && req.method === 'GET') {
    return sendJson(res, 200, {
      status: 'UP',
      timestamp: new Date().toISOString(),
      policy_version: 'fsm-v1'
    });
  }

  if (pathname === '/api/runs' && req.method === 'GET') {
    try {
      const runs = globalEnforcer.store.listRuns();
      return sendJson(res, 200, { runs });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if (pathname === '/api/enforce' && req.method === 'POST') {
    try {
      const request = await parseJsonBody(req);
      const result = await globalEnforcer.execute(request);
      const statusCode = result.decision === 'ALLOW' ? 200 : 403;
      return sendJson(res, statusCode, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if ((pathname === '/api/run' || pathname === '/api/scenario') && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const scenario = body.scenario || 'happy_path';
      const result = await executeScenario(scenario, { runId: body.runId });
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if (pathname === '/api/verify' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      if (!body.receipts || !body.proofData || !body.publicKeyPem) {
        return sendJson(res, 400, { error: 'Missing required fields: receipts, proofData, publicKeyPem' });
      }
      const report = await verifyResponse({
        receipts: body.receipts,
        proofData: body.proofData,
        publicKeyPem: body.publicKeyPem
      });
      return sendJson(res, 200, report);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Static Files Serving ---
  let filePath = path.join(STATIC_DIR, pathname === '/' ? 'index.html' : pathname);

  // Security check: prevent directory traversal
  if (!filePath.startsWith(STATIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access Denied');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for SPA if not found
      filePath = path.join(STATIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`  VeriRespond Security & ZK Dashboard Server Running`);
    console.log(`  URL: http://localhost:${PORT}`);
    console.log(`  Policy Version: fsm-v1 | Groth16 Prover: Active`);
    console.log(`======================================================\n`);
  });
}

module.exports = server;
