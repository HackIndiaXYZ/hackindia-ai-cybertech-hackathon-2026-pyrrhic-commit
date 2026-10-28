# Team Execution and Integration Plan

## 1. Team and ownership

Use separate branches and small, real commits. Do not fabricate commit authorship, test results, or work history.

### Asif — policy, simulator, and application integration
Own:
- Incident fixtures and mock state model.
- Typed action request/decision models in the shared contract.
- Deterministic planner.
- FSM policy gate, target allowlist, deny-by-default behavior.
- Controlled simulator executor; no arbitrary shell.
- Execution receipts integration points and dashboard/API integration.
- Policy/executor tests and end-to-end orchestration.

Suggested branch: `feat/policy-executor`

### Chirag — cryptographic evidence and ZK
Own:
- Canonical receipt serialization helpers if coordinated with Asif.
- Ed25519 key generation/loading for demo, signature creation/verification.
- SHA-256 receipt hash chain and independent validation.
- Circom circuit and its tests.
- snarkjs setup/prove/verify scripts and public input parser.
- Poseidon commitment calculation and receipt-to-proof binding verifier.
- Cryptographic/adversarial tests and proof manifest.

Suggested branch: `feat/crypto-zk`

### Joint ownership
- Freeze `PROTOCOL_AND_CONTRACTS.md` before parallel implementation.
- Review changes to shared schemas and proof public inputs.
- Integrate branches and resolve conflicts together.
- Run end-to-end tests and rehearse the judge demo.
- Keep a truthful task/status board in the GitHub project or README.

## 2. Repository layout target

Keep it small and predictable. Adjust names only by agreement:

```text
/
  README.md
  AGENTS.md
  docs/
    PROJECT_SPEC.md
    ARCHITECTURE_AND_THREAT_MODEL.md
    PROTOCOL_AND_CONTRACTS.md
    TEAM_EXECUTION.md
    TEST_AND_DEMO_RUNBOOK.md
  app/
    models.py
    planner.py
    policy_gate.py
    executor.py
    evidence.py
    verifier.py
    api.py
    dashboard.py
  circuits/
    fsm_v1.circom
    scripts/
    artifacts/       # only intentional, documented public artifacts
  tests/
    unit/
    integration/
    adversarial/
  scripts/
  .gitignore
  pyproject.toml or requirements.txt
  package.json / lockfile for the circuit toolchain
```

Do not create every suggested file if it adds no value. Keep circuit artifacts separate from source. Generated witnesses, local keys, caches, node_modules, virtual environments, and local environment files should be ignored.

## 3. Parallel work protocol

1. **First 15 minutes:** both agents read the six docs; confirm toolchain and run a minimal Circom proof spike. No feature coding before the spike is attempted.
2. **Freeze contracts:** agree exact field names, canonicalization, numeric IDs, public inputs, error statuses, and module paths. Commit the docs as the baseline.
3. **Branch work:** each person works only in owned modules. If a shared file must change, open a small PR/commit and message the other person before changing it.
4. **Integration checkpoint:** as soon as action schema, FSM gate, and proof command line exist, integrate them. Do not wait until every module is polished.
5. **End-to-end freeze:** stop adding features at the agreed cutoff; focus on tests, bug fixes, clean startup, and demo rehearsal.
6. **Final evidence:** record the actual commands run and results. Do not claim tests passed if they were not executed.

## 4. One-day time-box

Because proof tooling is untested and ZK is mandatory, the proof spike is the first technical gate.

### Gate 0 — toolchain feasibility (first 15–25 minutes)
- Confirm `circom`, `node`, `npm`, and `snarkjs` versions.
- Compile and prove a tiny known circuit, then independently verify it.
- Confirm both contributors can reproduce or at least one owner can run the pinned circuit environment.
- If this fails, resolve installation immediately. Do not build the whole app on the assumption that ZK will work.

### Gate 1 — contracts + skeleton (next 20 minutes)
- Commit shared contracts.
- Create package/environment files and health/startup command.
- Add test skeleton and a single run identifier path.

### Gate 2 — valid deterministic pipeline (next 60–90 minutes)
- Implement planner → gate → simulator executor → receipts.
- Implement signature/chain validation.
- Implement fixed circuit, proof generation and independent verification.
- Integrate as soon as each interface works.

### Gate 3 — adversarial tests and dashboard (next 45–60 minutes)
- Wrong target denied, no state mutation.
- Wrong transition denied.
- Receipt mutation and chain tampering fail.
- Commitment mismatch and invalid proof fail.
- Dashboard shows all statuses separately.

### Gate 4 — freeze and rehearsal (final 30–45 minutes)
- Fresh-process startup test.
- Run both demo paths twice.
- Fix only release-blocking issues.
- Prepare a recorded backup only if labelled accurately; never describe a recording as live execution.

Time blocks are targets, not promises. If time slips, remove optional features (LLM, animations, extra incident types), not correctness checks or honest failure reporting.

## 5. Git and review rules

- Start from the existing `main`; do not force-push or rewrite shared history.
- Each contributor commits only their own work under their real Git identity.
- Commit in coherent units with messages such as `feat(policy): enforce FSM transitions` or `test(zk): reject mismatched sequence commitment`.
- Keep changes small enough to review. No giant generated artifacts in commits.
- Before merging: inspect diff, run relevant tests, run formatting/lint if configured, check no secrets or local files were added.
- One contributor reviews the other's security-sensitive changes.
- Never claim a PR was reviewed, tests passed, or an artifact was generated unless that actually happened.

## 6. Integration contract

The minimum integration acceptance test must execute this full chain in one run:

`fixture → action requests → policy decisions → simulated state → four signed receipts → hash-chain validation → commitment recomputation → proof generation → independent proof verification → dashboard status`

The integration is not complete if the proof verifies but the receipt sequence is not cryptographically bound to its public inputs.
