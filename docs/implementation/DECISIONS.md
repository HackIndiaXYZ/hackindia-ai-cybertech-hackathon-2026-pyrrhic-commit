# Architecture & Security Decisions (VeriRespond)

## DEC-001: Enforcement Boundary Architecture
- **Decision:** Separate the proposal of actions from execution authorization. An AI agent proposing an action has zero execution privileges.
- **Mechanism:** The `ActionEnforcer` registers action handlers and only executes a handler after explicit authorization by the `PolicyGate`.
- **Guarantee:** Denied actions trigger zero execution side effects; handlers are never called.

## DEC-002: Evidence & Receipt Canonicalization
- **Decision:** Retain the frozen receipt schema, Ed25519 signatures with domain separator `VERIRESPOND-RECEIPT-V1\n`, and SHA-256 hash chaining.
- **Receipts:** Emitted only after simulated/actual execution succeeds.

## DEC-003: Honest ZK Status Reporting
- **Decision:** When proving artifacts (`.wasm`, `.zkey`) are absent, proof generation and verification must report `NOT_RUN` with clear reasoning, never `PASS` or fabricated success.
