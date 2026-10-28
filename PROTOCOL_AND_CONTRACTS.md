# Protocol and Shared Contracts — Frozen v1

This file is the interface contract for both contributors. Do not independently rename fields, change encodings, alter state/action IDs, or change public proof inputs. If a change is necessary, raise it first and update all dependent tests and docs together.

## 1. Fixed identifiers

### FSM states

| Numeric code | String |
|---:|---|
| 0 | `DETECTED` |
| 1 | `IP_BLOCKED` |
| 2 | `CREDENTIAL_ROTATED` |
| 3 | `SERVICE_ISOLATED` |
| 4 | `CONTAINED` |

### Actions

| Numeric code | Action ID | Transition |
|---:|---|---|
| 1 | `BLOCK_IP` | 0 → 1 |
| 2 | `ROTATE_CREDENTIAL` | 1 → 2 |
| 3 | `ISOLATE_SERVICE` | 2 → 3 |
| 4 | `CONFIRM_CONTAINMENT` | 3 → 4 |

Only this exact four-action sequence is in the v1 proof circuit. The policy gate must also validate targets and runtime state; the circuit only proves the FSM relation and commitment relation it encodes.

## 2. Typed action request

Illustrative JSON shape; implementations may use dataclasses/Pydantic internally but serialized field names must remain stable:

```json
{
  "schema_version": "1",
  "run_id": "decimal-field-element-string",
  "incident_id": "INC-DEMO-001",
  "policy_version": "fsm-v1",
  "action_id": "BLOCK_IP",
  "target_id": "SRC-DEMO-01",
  "request_id": "req-001"
}
```

Rules:
- `action_id` is a closed enum; reject unknown values.
- `target_id` must be a synthetic identifier in the policy allowlist.
- `run_id` is a canonical decimal representation of a field element in the proof system's scalar field. Generate it from a cryptographically secure random source and validate range; never parse it as a floating-point number.
- `request_id` is unique within a run and supports idempotency.
- No command, shell string, URL, raw SQL, credential, or arbitrary function name is accepted as an action field.
- Strictly reject malformed input and unsupported schema versions.

## 3. Policy decision

```json
{
  "schema_version": "1",
  "run_id": "same-run-id",
  "request_id": "req-001",
  "decision": "ALLOW",
  "reason_code": "FSM_TRANSITION_ALLOWED",
  "action_id": "BLOCK_IP",
  "target_id": "SRC-DEMO-01",
  "state_before": 0,
  "state_after": 1,
  "policy_version": "fsm-v1"
}
```

`decision` is `ALLOW` or `DENY`. For a denied request, `state_after` must equal `state_before`, and no execution receipt may claim the denied action was executed. The executor must reject a missing, malformed, mismatched, or denied decision.

## 4. Execution receipt

Use canonical JSON serialization before signing/hashing. For this project, define canonicalization in code once (UTF-8, sorted keys, no insignificant whitespace, fixed number/string types, no NaN/Infinity). Do not rely on default JSON serialization behavior without tests.

```json
{
  "schema_version": "1",
  "run_id": "same-run-id",
  "incident_id": "INC-DEMO-001",
  "sequence": 1,
  "request_id": "req-001",
  "action_id": "BLOCK_IP",
  "action_code": 1,
  "target_id": "SRC-DEMO-01",
  "state_before": 0,
  "state_after": 1,
  "decision": "ALLOW",
  "result": "EXECUTED",
  "policy_version": "fsm-v1",
  "previous_receipt_hash": "GENESIS",
  "receipt_hash": "sha256-hex",
  "signature": "base64-ed25519-signature",
  "signing_key_id": "demo-ed25519-v1"
}
```

Implementation detail: compute `receipt_hash` over the canonical receipt payload **excluding** `receipt_hash` and `signature`; sign a domain-separated byte string such as `VERIRESPOND-RECEIPT-V1\n` + canonical payload including `receipt_hash` but excluding `signature`. The next receipt's `previous_receipt_hash` equals the preceding receipt's `receipt_hash`. The first receipt uses the literal `GENESIS`. The independent verifier must recompute each hash and verify each signature against the pinned public key. Do not sign an object that includes its own signature.

The receipt must be created only after the executor reports the simulator mutation result. Never put secrets in receipts. Timestamps may be included for display but are not part of proof semantics; if included, use UTC ISO 8601 and document whether they are included in the signed payload (recommended: yes).

## 5. Denial event

A denied request should produce a separate `DENIED` audit event with `run_id`, `request_id`, attempted action/target, reason code, and unchanged state. It is not one of the four successful execution receipts used by the v1 proof. Never label it `EXECUTED`.

## 6. Commitment and proof binding

### Required proof statement

The circuit proves that the prover knows four action codes that:
1. are exactly the v1 sequence `1, 2, 3, 4`,
2. correspond to the FSM transitions `0→1→2→3→4`,
3. are bound to the public `run_id`,
4. produce the public Poseidon commitment `sequence_commitment`.

For the MVP, make the circuit fixed-length and fixed-policy. Avoid a generic arbitrary policy interpreter inside the circuit.

### Commitment definition

Use the `Poseidon(5)` construction from the pinned `circomlib` version over these five field elements in this exact order:

`[run_id, action_code_1, action_code_2, action_code_3, action_code_4]`

`sequence_commitment = Poseidon(inputs)`.

- `run_id` and the commitment are public circuit inputs.
- The four action codes are private witness inputs, constrained to the expected sequence and valid transitions.
- The proof builder and independent verifier must use the same Poseidon implementation and exact ordering.
- The independent verifier must validate all receipt signatures and chain links first, extract the four canonical action codes, recompute the commitment, and compare it to the proof's public `sequence_commitment`. It must also compare the proof's public `run_id` with the receipt run ID.
- A proof verifier returning `true` is insufficient if the public inputs are not matched to the verified receipt sequence.

**Important:** Because v1 constrains the exact four action codes, this is a narrow FSM-compliance proof, not a generic proof that arbitrary policy files are followed. Record the circuit source hash, compiler version, compiled R1CS hash, verification key hash, and setup artifact hashes in a manifest.

## 7. Independent verification result

Return a structured result, not a single boolean:

```json
{
  "policy_check": "PASS",
  "execution_check": "PASS",
  "receipt_signatures": "PASS",
  "hash_chain": "PASS",
  "commitment_binding": "PASS",
  "proof_generation": "PASS",
  "zk_verification": "PASS",
  "run_id": "same-run-id",
  "policy_version": "fsm-v1",
  "circuit_manifest_hash": "sha256-hex"
}
```

Any check that did not run must be `NOT_RUN`; any check that failed must be `FAIL`. Do not infer success from a file existing. A valid proof for mismatched public inputs is a failed binding check.

## 8. Compatibility rules

- Pin dependency versions and commit lockfiles.
- Pin circuit and verification-key artifacts to a manifest.
- No agent may change a field name, enum, state code, action code, proof input order, or canonicalization rule without explicit coordination.
- Do not commit private signing keys, secret setup contributions, raw witness files, or local environment files. Commit only public verifier artifacts and the reproducible setup instructions/artifact hashes appropriate for the demo.
- If a setup artifact is intentionally included for reproducible judging, label it demo-only and document its provenance and limitations.
