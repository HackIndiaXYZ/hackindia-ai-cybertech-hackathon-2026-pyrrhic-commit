# Project Specification

## 1. Goal

Build a reliable, judge-demonstrable prototype showing how a security response agent can be constrained by a deterministic policy and how an independent verifier can check evidence integrity and a narrowly defined zero-knowledge claim.

**Product promise:** “AI defends. Zero-knowledge proves it defended correctly.”

**Precise interpretation for this prototype:** a planner proposes actions; a policy gate authorizes only valid typed actions; the controlled simulator executes authorized actions; signed receipts and a hash chain provide tamper-evident evidence; a ZK circuit proves that a fixed action sequence satisfies a specific FSM and matches a public commitment recomputed from the receipts.

## 2. User-visible demo

The demo must show two paths:

### Path A — valid response
1. Load a synthetic incident.
2. Planner proposes the approved four-action response.
3. Gate checks each action and target against the policy and current state.
4. Executor applies simulated state changes in order.
5. Executor emits one signed receipt per executed action.
6. Receipt chain is validated.
7. Proof is generated from the action sequence and run identifier.
8. Independent verifier recomputes the commitment from the signed receipts and verifies the proof.
9. Dashboard shows distinct results for policy, execution, signatures, chain, commitment binding, and ZK verification.

### Path B — adversarial attempt
1. Planner or demo operator proposes an action against a disallowed target or an invalid transition.
2. Gate denies it before the executor mutates state.
3. A denial event is recorded separately, with a reason code.
4. State remains unchanged for the denied action.
5. Dashboard visibly reports `DENIED`; it must not portray the denial as a successful execution.
6. The canonical successful sequence can still be proved separately. Do not include the denied action in the four-action sequence unless the protocol and circuit are deliberately redesigned and retested.

## 3. Scope

### Required for the hackathon MVP
- Deterministic, reproducible incident fixture and planner.
- Typed action schema with strict validation.
- Versioned deterministic finite-state machine (FSM).
- Explicit target allowlist; no arbitrary shell commands.
- Separate policy-gate and executor modules.
- Simulated containment state changes in a local mock environment.
- Ed25519-signed receipts generated only by the executor/evidence service, not by the planner.
- SHA-256 hash chain with independent validation.
- Circom/snarkjs ZK circuit for the fixed FSM and sequence commitment.
- Independent verifier that checks signatures, chain, recomputed commitment, and proof.
- Dashboard with separate statuses and clear failure states.
- Valid-path and adversarial-path automated tests.
- Reproducible setup and demo instructions.

### Explicitly out of scope
- Real endpoint, firewall, cloud, identity-provider, or production-system changes.
- Arbitrary shell execution or unrestricted tool access.
- Real credentials, customer data, or real malware.
- A production-grade LLM agent. The planner may be deterministic; an LLM is optional only after the full pipeline works.
- Blockchain, TEE, on-chain verification, multi-tenant access control, distributed consensus, or production key management.
- Proving Ed25519 signature verification inside the circuit.
- Proving that simulated events correspond to external reality.
- Claims of complete privacy or zero information leakage.

## 4. Fixed FSM v1

The canonical sequence is fixed and ordered:

| Step | Action ID | Meaning | Required state before | State after |
|---|---|---|---|---|
| 1 | `BLOCK_IP` | Add the synthetic source IP to the simulator's block list | `DETECTED` | `IP_BLOCKED` |
| 2 | `ROTATE_CREDENTIAL` | Rotate a synthetic test credential identifier | `IP_BLOCKED` | `CREDENTIAL_ROTATED` |
| 3 | `ISOLATE_SERVICE` | Mark the allowlisted mock service isolated | `CREDENTIAL_ROTATED` | `SERVICE_ISOLATED` |
| 4 | `CONFIRM_CONTAINMENT` | Run deterministic checks over simulator state | `SERVICE_ISOLATED` | `CONTAINED` |

Numeric state/action encodings are frozen in `PROTOCOL_AND_CONTRACTS.md`. The circuit must reject reordered, missing, duplicated, unknown, or invalid actions. The policy gate must independently enforce the same state transitions at runtime.

## 5. Required dashboard statuses

Do not collapse these into one green badge:

- `POLICY`: `PASS`, `DENIED`, `FAIL`, or `NOT_RUN`
- `EXECUTION`: `PASS`, `FAIL`, or `NOT_RUN`
- `RECEIPT_SIGNATURES`: `PASS`, `FAIL`, or `NOT_RUN`
- `HASH_CHAIN`: `PASS`, `FAIL`, or `NOT_RUN`
- `COMMITMENT_BINDING`: `PASS`, `FAIL`, or `NOT_RUN`
- `ZK_PROOF_GENERATION`: `PASS`, `FAIL`, or `NOT_RUN`
- `INDEPENDENT_ZK_VERIFICATION`: `PASS`, `FAIL`, or `NOT_RUN`

Overall success is permitted only if every required valid-path check passed. A denied adversarial action is a successful policy-denial test, not a successful action execution.

## 6. Definition of done

The MVP is done only when:
- A fresh checkout can run the documented setup.
- The valid path completes from incident fixture through independent proof verification.
- A wrong-target or invalid-transition action is denied and causes no simulated state mutation.
- Mutating a receipt makes signature and/or chain validation fail.
- Reordering or deleting a receipt makes chain/sequence validation fail.
- Changing the proof's public input or proof bytes causes independent verification to fail.
- A sequence violating the FSM cannot generate a valid proof for the expected public commitment.
- Dashboard states reflect real function results.
- All commands and claims in the demo runbook have been executed by a team member and results recorded.
- Known limitations are stated honestly during the pitch.
