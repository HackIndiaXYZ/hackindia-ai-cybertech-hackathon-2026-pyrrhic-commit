pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * VeriRespond FSM v1 Circuit
 * Proves that:
 * 1. Prover knows 4 action codes matching the fixed canonical sequence [1, 2, 3, 4]
 * 2. Satisfies the FSM transitions: 0 (DETECTED) -> 1 (IP_BLOCKED) -> 2 (CREDENTIAL_ROTATED) -> 3 (SERVICE_ISOLATED) -> 4 (CONTAINED)
 * 3. Binds the private sequence to public run_id via Poseidon(5)
 * 4. Yields the public sequence_commitment
 */

template FSMv1() {
    // Public inputs
    signal input run_id;
    signal input sequence_commitment;

    // Private inputs (witness actions)
    signal input action_code_1;
    signal input action_code_2;
    signal input action_code_3;
    signal input action_code_4;

    // Enforce canonical sequence
    action_code_1 === 1;
    action_code_2 === 2;
    action_code_3 === 3;
    action_code_4 === 4;

    // Constrain explicit FSM transitions
    signal state_0;
    signal state_1;
    signal state_2;
    signal state_3;
    signal state_4;

    state_0 <== 0;
    state_1 <== state_0 + action_code_1;
    state_1 === 1;

    state_2 <== state_1 + (action_code_2 - 1);
    state_2 === 2;

    state_3 <== state_2 + (action_code_3 - 2);
    state_3 === 3;

    state_4 <== state_3 + (action_code_4 - 3);
    state_4 === 4;

    // Poseidon(5) hash commitment over:
    // [run_id, action_code_1, action_code_2, action_code_3, action_code_4]
    component hasher = Poseidon(5);
    hasher.inputs[0] <== run_id;
    hasher.inputs[1] <== action_code_1;
    hasher.inputs[2] <== action_code_2;
    hasher.inputs[3] <== action_code_3;
    hasher.inputs[4] <== action_code_4;

    // Commitment equality constraint
    hasher.out === sequence_commitment;
}

component main {public [run_id, sequence_commitment]} = FSMv1();
