/**
 * VeriRespond Persistent Run & Evidence Storage Engine
 * 
 * Durable, zero-dependency persistence layer using Node.js filesystem atomic journal / JSON store
 * or built-in node:sqlite. Designed for crash-resilience, restart recovery, and strict idempotency.
 */

const fs = require('fs');
const path = require('path');
const { canonicalize } = require('../crypto/canonical');

class DurableStore {
  /**
   * @param {string} storageDir - Base directory for durable data
   */
  constructor(storageDir = null) {
    this.storageDir = storageDir || path.resolve(__dirname, '../../data');
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }

    this.runsFile = path.join(this.storageDir, 'runs.json');
    this.receiptsFile = path.join(this.storageDir, 'receipts.json');
    this.requestsFile = path.join(this.storageDir, 'requests.json');

    this._initStorage();
  }

  _initStorage() {
    if (!fs.existsSync(this.runsFile)) fs.writeFileSync(this.runsFile, JSON.stringify({}), 'utf8');
    if (!fs.existsSync(this.receiptsFile)) fs.writeFileSync(this.receiptsFile, JSON.stringify({}), 'utf8');
    if (!fs.existsSync(this.requestsFile)) fs.writeFileSync(this.requestsFile, JSON.stringify({}), 'utf8');
  }

  _read(file) {
    try {
      const data = fs.readFileSync(file, 'utf8');
      return JSON.parse(data);
    } catch {
      return {};
    }
  }

  _writeAtomic(file, data) {
    const tmp = `${file}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, file);
  }

  /**
   * Save or update a run's state and metadata
   */
  saveRun(runId, runData) {
    const runs = this._read(this.runsFile);
    runs[runId] = {
      ...runs[runId],
      ...runData,
      run_id: runId,
      updated_at: new Date().toISOString()
    };
    this._writeAtomic(this.runsFile, runs);
    return runs[runId];
  }

  /**
   * Get run by runId
   */
  getRun(runId) {
    const runs = this._read(this.runsFile);
    return runs[runId] || null;
  }

  /**
   * List all persisted runs
   */
  listRuns() {
    const runs = this._read(this.runsFile);
    return Object.values(runs);
  }

  /**
   * Record a processed request for durable idempotency
   */
  recordRequest(requestId, record) {
    const requests = this._read(this.requestsFile);
    requests[requestId] = {
      ...record,
      recorded_at: new Date().toISOString()
    };
    this._writeAtomic(this.requestsFile, requests);
    return requests[requestId];
  }

  /**
   * Check if request was already processed
   */
  getRequest(requestId) {
    const requests = this._read(this.requestsFile);
    return requests[requestId] || null;
  }

  /**
   * Append a signed receipt to a run's chain
   */
  saveReceipt(runId, receipt) {
    const receipts = this._read(this.receiptsFile);
    if (!receipts[runId]) receipts[runId] = [];
    receipts[runId].push(receipt);
    this._writeAtomic(this.receiptsFile, receipts);
    return receipt;
  }

  /**
   * Get all receipts for a run in order
   */
  getReceipts(runId) {
    const receipts = this._read(this.receiptsFile);
    return receipts[runId] || [];
  }
}

module.exports = {
  DurableStore
};
