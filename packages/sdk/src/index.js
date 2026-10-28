/**
 * VeriRespond Client SDK
 * 
 * Programmatic interface for AI agents to propose actions through the
 * VeriRespond policy enforcement connector.
 */

const http = require('http');
const https = require('https');
const url = require('url');

class VeriRespondClient {
  /**
   * @param {object} options
   * @param {string} [options.baseUrl] - Connector URL (default: http://localhost:3000)
   * @param {number} [options.timeout] - Request timeout in ms (default: 5000)
   */
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || 'http://localhost:3000';
    this.timeout = options.timeout || 5000;
  }

  _request(method, endpoint, body = null) {
    return new Promise((resolve, reject) => {
      const parsed = url.parse(`${this.baseUrl}${endpoint}`);
      const isHttps = parsed.protocol === 'https:';
      const transport = isHttps ? https : http;

      const postData = body ? JSON.stringify(body) : null;
      const reqOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.path,
        method,
        timeout: this.timeout,
        headers: {
          'Content-Type': 'application/json'
        }
      };

      if (postData) {
        reqOptions.headers['Content-Length'] = Buffer.byteLength(postData);
      }

      const req = transport.request(reqOptions, res => {
        let resBody = '';
        res.on('data', chunk => resBody += chunk);
        res.on('end', () => {
          let parsedBody;
          try {
            parsedBody = resBody ? JSON.parse(resBody) : {};
          } catch {
            parsedBody = { raw: resBody };
          }

          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: parsedBody
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timed out after ${this.timeout}ms`));
      });

      req.on('error', reject);

      if (postData) {
        req.write(postData);
      }
      req.end();
    });
  }

  /**
   * Check connector health
   */
  async getHealth() {
    const res = await this._request('GET', '/api/health');
    return res.data;
  }

  /**
   * Retrieve policy specs, transitions, and public key
   */
  async getSpecs() {
    const res = await this._request('GET', '/api/specs');
    return res.data;
  }

  /**
   * Propose an action for policy mediation and execution
   * 
   * @param {object} actionRequest - { run_id, request_id, action_code, action_id, target_id }
   * @returns {Promise<object>} Execution decision, status, and receipt
   */
  async execute(actionRequest) {
    if (!actionRequest || !actionRequest.run_id || !actionRequest.request_id) {
      throw new Error('Action request must include run_id and request_id');
    }

    const res = await this._request('POST', '/api/enforce', actionRequest);
    return {
      success: res.statusCode === 200,
      statusCode: res.statusCode,
      decision: res.data.decision,
      status: res.data.status,
      receipt: res.data.receipt || null,
      reason: res.data.reason || null,
      outcome: res.data.outcome || null,
      isDuplicate: Boolean(res.data.isDuplicate)
    };
  }

  /**
   * Run a managed demonstration scenario
   */
  async runScenario(scenario = 'happy_path', options = {}) {
    const res = await this._request('POST', '/api/scenario', { scenario, ...options });
    return res.data;
  }

  /**
   * Verify receipts and proof data independently
   */
  async verify(receipts, proofData, publicKeyPem) {
    const res = await this._request('POST', '/api/verify', {
      receipts,
      proofData,
      publicKeyPem
    });
    return res.data;
  }
}

module.exports = {
  VeriRespondClient
};
