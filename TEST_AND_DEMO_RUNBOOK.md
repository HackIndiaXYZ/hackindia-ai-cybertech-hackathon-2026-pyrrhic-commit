# Test Strategy and Demo Runbook

## 1. Test layers

### Unit tests
- Schema rejects unknown action IDs, unsupported versions, malformed run IDs, missing fields, extra fields, and invalid types.
- Gate allows only the expected transition from the expected state.
- Gate denies wrong targets, wrong incident IDs, stale state, duplicate request IDs, and out-of-order actions.
- Denied action does not mutate simulator state.
- Executor refuses a missing, malformed, denied, or mismatched policy decision.
- Canonical serialization is deterministic across repeated runs.
- Receipt signature validates for the original payload and fails after a signed field is changed.
- Chain validator detects changed hashes, reordered entries, sequence gaps, wrong previous hash, and unexpected run ID.
- Poseidon commitment calculation is identical in proof builder and independent verifier.
- Circuit rejects incorrect action codes and invalid transitions.
- Independent verifier rejects mismatched run ID, commitment, verification key, or proof.
- Dashboard renders `FAIL` and `NOT_RUN` honestly.

### Integration tests
1. Happy path completes all required checks.
2. Wrong-target attempt is denied, state is unchanged, and a denial event is visible.
3. Invalid transition is denied.
4. Receipt tampering fails verification.
5. Receipt deletion/reordering fails chain/sequence checks.
6. A valid proof paired with receipts for another run fails binding.
7. A proof or public input altered after generation fails independent verification.
8. Proof generation failure never yields `zk_verification=PASS`.
9. Missing proof artifacts result in `NOT_RUN` or `FAIL`, never success.

## 2. Proof toolchain gate

Use the official Circom 2 documentation for installation and the proving workflow. The exact commands depend on installed versions; first record versions, then pin them. Expected flow:

1. Compile the circuit to R1CS and WASM.
2. Generate witness from input.
3. Run the demo-only Groth16 setup process and record artifact provenance.
4. Generate proof and public inputs.
5. Verify proof with the verification key in a separate verifier invocation.
6. Change a public input or proof byte and confirm verification fails.

Official references:
- Installation: https://docs.circom.io/getting-started/installation/
- Proof workflow: https://docs.circom.io/getting-started/proving-circuits/
- Witness generation: https://docs.circom.io/getting-started/computing-the-witness/

Do not copy a command from an outdated tutorial blindly. Check installed `circom --version`, `node --version`, and `snarkjs --version`; use the current CLI help for any version-specific syntax.

## 3. Live demo sequence (target 3–4 minutes)

1. **Set context:** “This is a synthetic, local incident. No production systems or real credentials are connected.”
2. **Show policy:** identify the FSM version and four approved action transitions.
3. **Run valid response:** show the planner's typed actions and the policy gate's decisions.
4. **Show simulated changes:** source blocked, synthetic credential rotated, mock service isolated, containment check passed.
5. **Show evidence:** four receipts, each signature verified, chain verified, public key/key ID and run ID visible without exposing the private key.
6. **Show proof:** display proof-generation status and the public run ID/sequence commitment. Do not reveal private witness inputs unless intentionally shown as a debugging artifact.
7. **Show independent verifier:** run the verification function separately from the proof builder; show signatures, chain, binding, and ZK verification as distinct results.
8. **Attack test:** request a disallowed target. Show denial reason and unchanged state.
9. **Tamper test:** change a copy of a receipt or alter the public commitment; show the appropriate validation fails.
10. **Explain limitations:** proof establishes the fixed FSM relation and commitment binding; it does not prove real-world execution or policy correctness.

## 4. Backup plan and status labels

- If live proof generation is slow but works, measure it and state the measured result.
- If using a pre-generated proof, label it `PREPARED ARTIFACT`; show independent verification and explain what was prepared.
- If proof generation fails, say so and show the failure honestly. Do not substitute a hardcoded `true`, sample output, or fake proof.
- A screen recording is a backup presentation, not a live demo.
- Never use a “green” overall status if any required check is `FAIL` or `NOT_RUN`.

## 5. Final release checklist

- [ ] Fresh process starts using documented steps.
- [ ] Both valid and adversarial paths work.
- [ ] No real credentials or external targets are used.
- [ ] Valid path: all required statuses are actual `PASS`.
- [ ] Wrong target: `DENIED`; simulated state unchanged.
- [ ] Receipt tampering is detected.
- [ ] Receipt ordering/deletion is detected.
- [ ] Proof public inputs are matched to verified receipt sequence.
- [ ] Independent verifier does not trust a boolean from the proof builder.
- [ ] Failure cases are visible in the UI.
- [ ] No private keys, secrets, raw witness files, or environment files are committed.
- [ ] Team has run the demo twice and can explain each cryptographic claim.
- [ ] Judges are told this is a hackathon prototype and not production-ready response automation.
