# VeriRespond — HackIndia 2026 (Pyrrhic Commit)

**Repository:** `HackIndiaXYZ/hackindia-ai-cybertech-hackathon-2026-pyrrhic-commit`  
**Team:** Pyrrhic Commit — Mohd Asif and Chirag Vishnoi  
**Event context:** HackIndia AI & CyberTech Hackathon 2026  
**Track:** AI & CyberTech — Zero-Knowledge Evidence & Incident Containment  
**Status:** Locally verified end-to-end implementation and luxury white React dashboard.

## Live Deployments

- **Live Application & Dashboard:** [https://hackindia-ai-cybertech-hackathon-2026-h9v8.onrender.com](https://hackindia-ai-cybertech-hackathon-2026-h9v8.onrender.com)
- **Live API Status Endpoint:** [https://hackindia-ai-cybertech-hackathon-2026-h9v8.onrender.com/api/status](https://hackindia-ai-cybertech-hackathon-2026-h9v8.onrender.com/api/status)

---

## Read these documents in this order

1. `PROJECT_SPEC.md` — what we are building, what is in scope, acceptance criteria.
2. `ARCHITECTURE_AND_THREAT_MODEL.md` — components, trust boundaries, threats and security claims.
3. `PROTOCOL_AND_CONTRACTS.md` — frozen action IDs, FSM, receipt format, hash chain and proof binding.
4. `TEAM_EXECUTION.md` — file ownership, branch rules, integration gates and time-boxed plan.
5. `TEST_AND_DEMO_RUNBOOK.md` — tests, commands, demo flow and judge-safe claims.
6. `AGENTS.md` — mandatory instructions for Antigravity agents.

---

## One-minute product definition

VeriRespond demonstrates a constrained security-response workflow. A planner proposes typed actions. A deterministic policy gate validates the target, action, incident, and state transition. A separate controlled executor performs only approved simulated actions in an isolated mock environment. The trusted executor emits signed receipts; receipts are chained with SHA-256. A Circom/snarkjs circuit proves that the canonical four-action sequence satisfies the versioned FSM and is bound to a public Poseidon commitment. An independent verifier checks receipt signatures, chain integrity, the commitment, and the ZK proof. The luxury executive dashboard reports each check separately.

---

## Non-negotiable honesty rules

- Never mark a check `PASS` unless the corresponding verification function actually ran and returned success.
- Never use a cached/precomputed proof while labelling it as generated live. If a prepared artifact is used, label it `PREPARED ARTIFACT`.
- If proof generation or verification fails, display `FAIL` or `NOT RUN`; never fake a successful proof.
- A valid proof establishes only the relation encoded by the circuit for its public inputs. It does **not** prove that real-world actions happened, that a detector was correct, or that the policy itself is safe.
- A signature establishes that the corresponding private key signed the receipt; it does not independently establish the receipt's real-world truth.
- A hash chain detects alteration/reordering relative to the retained chain; by itself it cannot prevent deletion of the entire log or prove that the log was complete.
- This is a controlled hackathon simulation, not production-ready autonomous incident response.
