/**
 * Frozen FSM transitions and state definitions according to PROTOCOL_AND_CONTRACTS.md
 */

const FSM_TRANSITIONS = {
  1: { id: 'BLOCK_IP', name: 'Block Malicious IP', from: 0, to: 1, allowedTargets: ['SRC-DEMO-01', 'SRC-DEMO-02'] },
  2: { id: 'ROTATE_CREDENTIAL', name: 'Rotate Compromised Credential', from: 1, to: 2, allowedTargets: ['CRED-DEMO-01', 'CRED-DEMO-02'] },
  3: { id: 'ISOLATE_SERVICE', name: 'Isolate Impacted Service', from: 2, to: 3, allowedTargets: ['SVC-DEMO-01', 'SVC-DEMO-02'] },
  4: { id: 'CONFIRM_CONTAINMENT', name: 'Confirm System Containment', from: 3, to: 4, allowedTargets: ['CONTAINMENT-CHECK'] }
};

const STATE_NAMES = {
  0: 'DETECTED',
  1: 'IP_BLOCKED',
  2: 'CREDENTIAL_ROTATED',
  3: 'SERVICE_ISOLATED',
  4: 'CONTAINED'
};

module.exports = {
  FSM_TRANSITIONS,
  STATE_NAMES
};
