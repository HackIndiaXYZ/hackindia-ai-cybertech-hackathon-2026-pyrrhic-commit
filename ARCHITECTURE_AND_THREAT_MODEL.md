# Architecture and Threat Model

## 1. Architecture

```text
Synthetic incident fixture
        |
        v
Planner (deterministic; untrusted proposer)
        |
        v
Typed action request
        |
        v
Policy Gate ---- deny/reason event ----> Evidence stream
        |
  authorized request only
        v
Controlled Executor (trusted for simulated state mutation)
        |
        +----> mock state
        |
        +----> signed execution receipt
                    |
                    v
             SHA-256 receipt chain
                    |
          +---------+----------+
          |                    |
          v                    v
 Independent evidence      Proof input builder
 verifier                  (same run ID + action IDs)
          |                    |
          |                    v
          |               Circom circuit
          |                    |
          |               snarkjs proof
          +----------+---------+
                     v
           Independent verification result
                     |
                     v
                  Dashboard
```

## 2. Trust boundaries

- **Planner:** untrusted. It may propose wrong, duplicate, reordered, or unauthorized actions. It has no executor signing key and no direct access to state-mutation functions.
- **Policy gate:** enforcement boundary. It validates schema, run/incident identity, action ID, target allowlist, current state, policy version, and idempotency. Deny by default.
- **Executor:** trusted component for the *simulated* state transition. It must accept only a gate-authorized decision object, validate the authorization context, mutate only named mock state, and create receipts. It exposes no arbitrary command execution.
- **Evidence service:** trusted to hold the demo signing key and construct receipt-chain entries. Key access is not available to the planner or dashboard.
- **Proof builder:** transforms the canonical receipt sequence into circuit inputs. Its output is untrusted until checked by the independent verifier.
- **Independent verifier:** must not simply trust status booleans from the planner, executor, or dashboard. It independently validates receipts, chain links, commitment, and proof using pinned verification artifacts.
- **Dashboard:** presentation only. It must render actual verifier results and cannot set a result to success on its own.
- **Mock environment:** local synthetic data only; no external network or real security-control integration.

## 3. Adversaries and abuse cases

| Threat | Control | Required test |
|---|---|---|
| Planner requests a disallowed IP/service | Exact allowlist and typed action schema | Wrong target denied; state unchanged |
| Planner skips/reorders an action | FSM transition check | Invalid transition denied |
| Planner submits unknown action or extra fields | Strict schema / enum validation | Unknown ID and malformed payload rejected |
| Planner tries to call executor directly | Module/API boundary; executor accepts gate decision only | Direct unauthorised executor request rejected |
| Receipt modified after signing | Ed25519 signature verification | Alter signed field; verification fails |
| Receipt removed/reordered | Sequence numbers + previous-hash chain + expected count | Missing/reordered entry fails validation |
| Different receipt sequence is paired with proof | Recompute Poseidon commitment from verified receipts and compare with proof public input | Mismatch fails |
| Old proof replayed for a different run | Bind `run_id` into public input and Poseidon commitment | Changed run ID fails commitment/proof verification |
| Invalid FSM sequence presented to circuit | Circuit constraints enforce fixed transitions | Witness/proof generation fails or independent verification fails |
| Dashboard falsely claims success | Dashboard consumes verifier output only | Unit test for failed/absent verifier result |
| Secret leaked into logs/repository | Synthetic values, secret scanning, ignore generated secrets/witnesses | Search logs and Git diff for forbidden values |
| Whole log deleted or signing key compromised | Explicit limitation; external anchoring/key management out of MVP | Document, do not claim prevented |

## 4. Security principles

1. **Fail closed:** malformed or incomplete requests are denied.
2. **Separation of duties:** the planner proposes; the gate authorizes; the executor mutates simulator state; the verifier checks evidence.
3. **No arbitrary execution:** actions map to fixed simulator functions.
4. **Least privilege:** only the evidence component can access the demo signing key.
5. **Determinism:** identical fixture + policy + action sequence yields reproducible state and protocol inputs, apart from an explicit run identifier.
6. **Evidence minimization:** use synthetic IDs and categories; never include passwords, tokens, real IPs, or real personal data in receipts.
7. **Observable failures:** report failed checks explicitly; never silently fall back to a fake success.
8. **Auditability:** record policy version, code/circuit version, and verification artifact hashes in a run manifest.

## 5. Precise security claims

- **Ed25519 signature:** supports verification that a receipt was signed by the holder of the configured private key, assuming the public key is trusted and the key was not compromised. It does not prove the event is truthful.
- **SHA-256 hash chain:** detects alteration, reordering, and many forms of deletion when checked against retained entries and expected sequence metadata. It does not prove the original log was complete and cannot prevent truncation if no trusted final commitment/anchor exists.
- **ZK proof:** proves the witness satisfies the compiled circuit constraints for the supplied public inputs, under the proof system's assumptions and trusted setup. It does not prove a real-world action occurred or that the policy is appropriate.
- **Receipt-to-proof binding:** the verifier validates the receipt signatures and chain, extracts the canonical four action IDs and run ID, recomputes the Poseidon commitment, and requires exact equality with the commitment and run ID in the proof's public inputs. This prevents a valid proof for a different sequence from being presented alongside these receipts, assuming the verifier and circuit are correct.
- **Privacy:** only fields designated private in the circuit are hidden by the proof system. Public inputs, receipt content, UI fields, logs, and timing can still disclose information. Do not claim “zero data leakage.”
- **Trusted setup:** Groth16 uses a circuit-specific setup. The hackathon setup is for a demonstration and is not a production ceremony. Record the setup process and artifact hashes.

## 6. Sources used for design

- Circom 2 documentation: circuit constraints, witness generation, proof generation and verification, and Groth16 setup: https://docs.circom.io/ and https://docs.circom.io/getting-started/proving-circuits/
- OWASP Logging Cheat Sheet: log event integrity, avoid secrets in logs, sanitize untrusted data, and test logging failures: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
