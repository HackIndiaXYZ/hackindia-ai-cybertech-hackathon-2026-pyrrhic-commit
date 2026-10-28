/**
 * VeriRespond — Action Enforcement Boundary
 * 
 * Strict mediation layer between untrusted action proposers (e.g. AI agents)
 * and execution handlers.
 * 
 * Non-negotiable security invariant:
 * - Handlers are ONLY invoked if the PolicyGate returns ALLOW for the exact request.
 * - Denials emit denial evidence, mutate zero state, and guarantee zero handler execution.
 * - Request replay and duplicate execution prevention.
 */

const { FSM_TRANSITIONS, STATE_NAMES } = require('./constants');
const { signReceipt } = require('../crypto/evidence');
const { DurableStore } = require('../storage/store');

class PolicyGate {
  constructor(options = {}) {
    this.policyVersion = options.policyVersion || 'fsm-v1';
    this.transitions = options.transitions || FSM_TRANSITIONS;
  }

  /**
   * Evaluate action request against FSM transitions and target allowlists
   * 
   * @param {number} currentState - Integer state code 0..4
   * @param {object} request - Typed ActionRequest
   * @returns {{ decision: 'ALLOW'|'DENIED', reason?: string, transition?: object }}
   */
  evaluate(currentState, request) {
    if (!request || typeof request !== 'object') {
      return { decision: 'DENIED', reason: 'Malformed action request: expected object' };
    }

    // Enforce strict known fields validation
    const allowedKeys = new Set(['schema_version', 'run_id', 'incident_id', 'policy_version', 'action_id', 'action_code', 'target_id', 'request_id', 'sequence']);
    for (const key of Object.keys(request)) {
      if (!allowedKeys.has(key)) {
        return {
          decision: 'DENIED',
          reason: `Unexpected or unauthorized request parameter: '${key}'`
        };
      }
    }

    const { action_id, action_code, target_id, policy_version } = request;

    if (policy_version && policy_version !== this.policyVersion) {
      return { decision: 'DENIED', reason: `Unsupported policy version: ${policy_version}. Expected ${this.policyVersion}` };
    }

    // Resolve transition either by action_code or action_id
    let transition = null;
    let code = action_code;

    if (code !== undefined && this.transitions[code]) {
      transition = this.transitions[code];
    } else if (action_id) {
      for (const [c, trans] of Object.entries(this.transitions)) {
        if (trans.id === action_id) {
          transition = trans;
          code = Number(c);
          break;
        }
      }
    }

    if (!transition) {
      return { decision: 'DENIED', reason: `Unknown or unsupported action: id='${action_id}', code='${action_code}'` };
    }

    // Validate current FSM state
    if (currentState !== transition.from) {
      const fromName = STATE_NAMES[transition.from] || transition.from;
      const currName = STATE_NAMES[currentState] || currentState;
      return {
        decision: 'DENIED',
        reason: `Invalid state transition: Action ${transition.id} requires state ${fromName} (${transition.from}), but current state is ${currName} (${currentState})`
      };
    }

    // Validate target allowlist
    if (!target_id || !transition.allowedTargets.includes(target_id)) {
      return {
        decision: 'DENIED',
        reason: `Target '${target_id}' is not in authorized allowlist for action ${transition.id} [${transition.allowedTargets.join(', ')}]`
      };
    }

    return {
      decision: 'ALLOW',
      action_code: code,
      transition
    };
  }
}

class ActionEnforcer {
  /**
   * @param {object} options
   * @param {PolicyGate} options.policyGate
   * @param {object} options.authorityKeypair - { publicKeyPem, privateKeyPem }
   */
  constructor(options = {}) {
    this.policyGate = options.policyGate || new PolicyGate();
    this.authorityKeypair = options.authorityKeypair;
    this.store = options.store || new DurableStore();
    this.handlers = new Map();
    this.processedRequests = new Map(); // requestId -> execution record
    this.runStates = new Map(); // runId -> currentState (integer)
    this.runChains = new Map(); // runId -> previousReceiptHash
    this.runLocks = new Map(); // runId -> Promise chain for sequential execution
  }

  /**
   * Register an action execution handler
   * 
   * @param {number|string} action - Action code or action ID
   * @param {Function} handler - async (request, context) => outcome
   */
  registerHandler(action, handler) {
    if (typeof handler !== 'function') {
      throw new Error(`Handler for ${action} must be a function`);
    }
    this.handlers.set(action, handler);
  }

  /**
   * Get current state of a run
   */
  getRunState(runId) {
    if (this.runStates.has(runId)) {
      return this.runStates.get(runId);
    }
    // Check durable store
    const persisted = this.store ? this.store.getRun(runId) : null;
    if (persisted && persisted.state !== undefined) {
      this.runStates.set(runId, persisted.state);
      return persisted.state;
    }
    return 0; // Default state 0: DETECTED
  }

  /**
   * Execute an action request through the deterministic policy enforcement boundary
   * 
   * @param {object} request - Typed ActionRequest
   * @param {object} [context] - Execution context (e.g. simulated environment)
   * @returns {Promise<object>} Structured result
   */
  async execute(request, context = {}) {
    if (!request || !request.request_id || !request.run_id) {
      return {
        status: 'DENIED',
        decision: 'DENIED',
        reason: 'Missing required request fields: request_id and run_id are mandatory',
        receipt: null
      };
    }

    const { run_id } = request;

    // Per-run lock to serialize concurrent requests and eliminate race conditions
    const previousLock = this.runLocks.get(run_id) || Promise.resolve();
    let releaseLock;
    const currentLock = new Promise(resolve => { releaseLock = resolve; });
    this.runLocks.set(run_id, previousLock.then(() => currentLock));

    try {
      await previousLock;
      return await this._executeInternal(request, context);
    } finally {
      releaseLock();
    }
  }

  async _executeInternal(request, context) {

    const { run_id, request_id } = request;

    // Idempotency check: prevent duplicate replay of identical request_id
    const existing = this.processedRequests.get(request_id) || (this.store ? this.store.getRequest(request_id) : null);
    if (existing) {
      return {
        ...existing,
        isDuplicate: true,
        notice: `Request ${request_id} has already been processed with decision ${existing.decision}`
      };
    }

    const currentState = this.getRunState(run_id);

    // 1. Policy Gate Evaluation (Fail closed)
    let gateResult;
    try {
      gateResult = this.policyGate.evaluate(currentState, request);
    } catch (err) {
      gateResult = { decision: 'DENIED', reason: `Policy evaluation error: ${err.message}` };
    }

    if (gateResult.decision !== 'ALLOW') {
      const denialRecord = {
        status: 'DENIED',
        decision: 'DENIED',
        reason: gateResult.reason,
        run_id,
        request_id,
        state: currentState,
        receipt: null,
        timestamp: new Date().toISOString()
      };
      if (this.store) {
        this.store.recordRequest(request_id, denialRecord);
      }
      this.processedRequests.set(request_id, denialRecord);
      return denialRecord;
    }

    // 2. Resolve Registered Handler
    const transition = gateResult.transition;
    const actionCode = gateResult.action_code;
    const handler = this.handlers.get(actionCode) || this.handlers.get(transition.id);

    if (!handler) {
      const noHandlerRecord = {
        status: 'DENIED',
        decision: 'DENIED',
        reason: `No execution handler registered for action ${transition.id} (code ${actionCode})`,
        run_id,
        request_id,
        state: currentState,
        receipt: null
      };
      this.processedRequests.set(request_id, noHandlerRecord);
      return noHandlerRecord;
    }

    // 3. Execute Registered Handler
    const stateBefore = currentState;
    const stateAfter = transition.to;
    let executionOutcome;

    try {
      executionOutcome = await handler(request, { ...context, stateBefore, stateAfter });
    } catch (handlerErr) {
      // Handler failure fails closed: state is NOT mutated
      return {
        status: 'ERROR',
        decision: 'ALLOW',
        reason: `Handler execution error: ${handlerErr.message}`,
        run_id,
        request_id,
        state: currentState,
        receipt: null
      };
    }

    // Mutate state only after successful handler execution
    this.runStates.set(run_id, stateAfter);
    if (this.store) {
      this.store.saveRun(run_id, { state: stateAfter, last_action: transition.id });
    }

    // 4. Evidence Receipt Generation
    let signedReceipt = null;
    if (this.authorityKeypair && this.authorityKeypair.privateKeyPem) {
      let previousHash = this.runChains.get(run_id);
      if (!previousHash && this.store) {
        const storedReceipts = this.store.getReceipts(run_id);
        if (storedReceipts.length > 0) {
          previousHash = storedReceipts[storedReceipts.length - 1].receipt_hash;
        }
      }
      if (!previousHash) previousHash = 'GENESIS';

      const sequence = (request.sequence !== undefined) ? request.sequence : (stateBefore + 1);

      const rawReceipt = {
        schema_version: '1',
        run_id,
        incident_id: request.incident_id || 'INC-DEMO-001',
        sequence,
        request_id,
        action_id: transition.id,
        action_code: actionCode,
        target_id: request.target_id,
        state_before: stateBefore,
        state_after: stateAfter,
        decision: 'ALLOW',
        result: 'EXECUTED',
        policy_version: this.policyGate.policyVersion,
        previous_receipt_hash: previousHash
      };

      signedReceipt = signReceipt(rawReceipt, this.authorityKeypair.privateKeyPem);
      this.runChains.set(run_id, signedReceipt.receipt_hash);
      if (this.store) {
        this.store.saveReceipt(run_id, signedReceipt);
      }
    }

    const successRecord = {
      status: 'EXECUTED',
      decision: 'ALLOW',
      stateBefore,
      stateAfter,
      action_id: transition.id,
      action_code: actionCode,
      target_id: request.target_id,
      receipt: signedReceipt,
      outcome: executionOutcome
    };

    if (this.store) {
      this.store.recordRequest(request_id, successRecord);
    }
    this.processedRequests.set(request_id, successRecord);
    return successRecord;
  }
}

module.exports = {
  PolicyGate,
  ActionEnforcer
};
