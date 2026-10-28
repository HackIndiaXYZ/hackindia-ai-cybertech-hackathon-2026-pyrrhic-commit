# Antigravity Agent Instructions — VeriRespond

## 1. Authority and operating mode

You are implementing the VeriRespond hackathon MVP. Work autonomously within the assigned module, but follow the source-of-truth documents:

1. `docs/PROJECT_SPEC.md`
2. `docs/ARCHITECTURE_AND_THREAT_MODEL.md`
3. `docs/PROTOCOL_AND_CONTRACTS.md`
4. `docs/TEAM_EXECUTION.md`
5. `docs/TEST_AND_DEMO_RUNBOOK.md`

Do not silently change security guarantees, public proof inputs, schema fields, enum values, state/action IDs, receipt canonicalization, or module ownership. If a document conflicts with another, stop and report the conflict instead of guessing.

## 2. Non-negotiable rules

- Do not add real-world offensive capability, arbitrary shell execution, external target access, or real credential handling. This is a local synthetic simulation.
- Do not allow the planner or dashboard to access the signing private key.
- Do not let the executor mutate state without an explicit valid gate authorization.
- Fail closed on malformed, unknown, stale, mismatched, or unauthorized requests.
- Never hardcode `PASS`, `verified=true`, or a proof success response.
- Never generate a fake proof or claim that a prepared proof was generated live.
- Do not state that ZK proves real-world execution, truth of logs, or policy correctness.
- Do not commit private keys, secrets, `.env` files, raw witnesses, local caches, virtual environments, `node_modules`, or huge generated files.
- Never invent test results. Run the tests and report exact outcomes.

## 3. Before coding

1. Read all five source-of-truth docs.
2. Inspect the current repository, current branch, and existing files; do not assume the repository is empty or overwrite uninspected work.
3. Check the toolchain and perform the minimal Circom/snarkjs proof spike first.
4. Confirm the exact files you own and the shared interfaces with the other agent.
5. If the repository differs from the target layout, preserve useful existing work and explain the required adaptation.

## 4. Implementation quality

- Prefer the smallest reliable implementation over speculative features.
- Use explicit types, closed enums, strict validation, bounded inputs, deterministic behavior, and clear error codes.
- Separate policy, execution, evidence generation, proof generation, verification, and UI responsibilities.
- Keep proof generation and independent proof verification as separate operations.
- Verify receipt signatures and hash chain before computing the receipt-to-proof commitment.
- Compare the verifier's computed commitment and run ID with the exact public inputs passed to proof verification.
- Record circuit source/compiler/dependency versions and artifact hashes.
- Add unit tests for every security-sensitive condition and at least one end-to-end test.
- Keep logs sanitized; do not log private keys, credentials, raw tokens, or unnecessary personal data.

## 5. Git behavior

- Work only on the assigned feature branch.
- Make small, coherent commits with truthful messages.
- Do not rewrite shared history or force-push.
- Do not modify another contributor's owned files without coordinating.
- Do not merge branches or change shared contracts silently.
- Before reporting completion, show changed files, commands actually run, test outcomes, known limitations, and any integration blockers.

## 6. Required final report from each agent

Return:
1. Files created/modified.
2. Features implemented.
3. Exact setup/run/test commands executed.
4. Test results (pass/fail/not run).
5. Security assumptions and limitations.
6. Any dependency/toolchain issue.
7. Contract changes requested (do not make them unilaterally).
8. Commit hashes for actual commits, if commits were made.
9. One explicit statement: “I did not hardcode verification success” — only if true.
