<div align="center">

# Agent FailSafe

**The Autonomous Agent's Software Development Toolkit**

*Deterministic guardrails for agentic code generation. Fail fast. Build failure DNA. Iterate safely.*

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pypi-agent--failsafe-blue.svg)](https://pypi.org/project/agent-failsafe/)
[![Agent-OS Compatible](https://img.shields.io/badge/agent--os-compatible-green.svg)](https://github.com/microsoft/agent-governance-toolkit)
[![AgentMesh Compatible](https://img.shields.io/badge/agentmesh-compatible-green.svg)](https://github.com/microsoft/agent-governance-toolkit)
[![Agent SRE Compatible](https://img.shields.io/badge/agent--sre-compatible-green.svg)](https://github.com/microsoft/agent-governance-toolkit)
[![Part of Agent Governance Ecosystem](https://img.shields.io/badge/ecosystem-Agent_Governance-blueviolet)](https://github.com/microsoft/agent-governance-toolkit)

> **Part of the [Agent Governance Ecosystem](https://github.com/microsoft/agent-governance-toolkit)** — Complements [Agent OS](https://github.com/microsoft/agent-governance-toolkit) (permissions), [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) (identity), [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) (isolation), and [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) (reliability) with SDLC-native risk governance

```
pip install agent-failsafe
```

[The Missing Layer](#the-missing-layer) • [How It Works](#how-it-works) • [Shadow Genome](#shadow-genome) • [Quick Start](#quick-start) • [Two Governance Models](#two-governance-models) • [Architecture](#architecture) • [Modules](#modules) • [Contributing](#contributing)

</div>

---

## The Missing Layer

The Agent Governance Toolkit answers the question: **"Is this agent allowed to do this?"**

Agent OS checks permissions. AgentMesh verifies identity. The Hypervisor enforces execution boundaries. Agent SRE monitors health. Together they form a comprehensive runtime governance layer.

But there's a question none of them ask: **"Is what this agent is building any good?"**

An autonomous agent with full permissions can still generate insecure authentication stubs, create architecturally orphaned files, introduce complexity that violates maintainability thresholds, or make API assumptions that drift from the actual interface. The toolkit will let all of that through — because none of it violates a *permission*.

Agent FailSafe governs the **software development cycle itself**. Not whether an agent *can* write a file, but whether what it's *writing* is safe to ship. It risk-grades every development action based on what domain the code touches, records every decision in a tamper-evident ledger, and builds a persistent failure DNA — the Shadow Genome — that turns every failed code generation into navigational context for the next iteration.

---

## Two Governance Models

The toolkit and FailSafe solve related problems from fundamentally different perspectives. They complement each other — neither subsumes the other.

| Concern | Toolkit asks | FailSafe asks |
|---------|-------------|---------------|
| **Should this proceed?** | Does this agent have permission? (declarative policy rules) | Is this development action inherently risky? (domain-native risk classification) |
| **Execution isolation** | How trusted is this agent? (reputation-based ring assignment) | What is this agent about to touch? (action-based sandboxing) |
| **Audit trail** | Can we prove governance happened? (compliance artifact for auditors) | Can the next iteration trust its failure history? (communication medium for the agent) |
| **Observability** | Is the policy engine healthy? (ops telemetry) | Is this agent's development work proceeding or stuck? (velocity under governance) |
| **Failure handling** | Deny and log | Deny, record why, classify the failure mode, feed it forward |

A brand-new agent with no history writing authentication code should be sandboxed — but reputation-based isolation can't catch that because there's no reputation yet. FailSafe's action-based risk grading can.

An agent with a perfect track record generating crypto key handling should still hit an L3 gate — because the risk is in the *nature of the code*, not the identity of the writer.

The toolkit governs the agent. FailSafe governs what the agent builds.

---

## How It Works

FailSafe governs the agentic software development cycle end-to-end:

1. **Risk-grade every development action** — File writes, schema changes, auth modifications, and dependency additions are classified L1/L2/L3 based on what domain the code touches
2. **Sandbox high-risk code generation** — L3 operations (auth, crypto, payments, migrations) run in `RING_3_SANDBOX` regardless of agent reputation; repeated violations trigger kill-switch escalation
3. **Record every decision as iteration context** — Hash-chained ledger entries capture what the agent attempted, why it was allowed or denied, and the full risk context — not for auditors, but for the agent's next development cycle
4. **Build failure DNA** — Denied code generations, quarantine events, and kill-switch triggers feed the Shadow Genome — a persistent, codebase-specific failure memory
5. **Iterate from failure** — Subsequent development cycles inherit accumulated failure patterns, turning every denied attempt into navigational context

FailSafe integrates with the toolkit at four points, each adding an SDLC-specific perspective the toolkit doesn't have on its own:

| Integration | What the toolkit does | What FailSafe adds |
|-------------|----------------------|-------------------|
| **Agent OS** | Permission-based tool call interception | Risk-grades the *content* of code generation, not just whether the agent is allowed |
| **AgentMesh** | Identity verification and trust scoring | Maps development track record into trust — an agent's governance history becomes its reputation |
| **Agent Hypervisor** | Reputation-based execution rings | Action-based sandboxing — crypto code is RING_3 regardless of who writes it |
| **Agent SRE** | Policy engine health metrics | Development velocity under governance — are guardrails helping or blocking? |

---

## Shadow Genome

The Shadow Genome is FailSafe's persistent failure DNA — a codebase-specific knowledge base of how autonomous development fails and what to do about it. Every failure mode is recorded with:

- **What failed** — the file, pattern, or architectural decision that was rejected
- **Why it failed** — the specific violation: security stub left in auth code, complexity breach in a generated module, orphaned file not connected to the build path, API assumption that drifted from the actual interface
- **The pattern to avoid** — a generalized lesson extracted from the specific failure
- **Whether remediation succeeded** — closing the loop so the same failure doesn't recur

In practice, this means an agent that generates a database migration touching credential tables will:
1. Hit the L3 risk gate (denied, sandboxed)
2. Have that denial recorded with full context in the ledger
3. See the failure classified in the Shadow Genome (e.g., `SECURITY_STUB` or `COMPLEXITY_VIOLATION`)
4. On the next development iteration, inherit that context — knowing this path was tried and why it failed

The toolkit's audit log proves governance happened. The Shadow Genome teaches the agent *how to develop better next time*. One is a compliance record. The other is a debugging context built from accumulated failure DNA.

---

## Quick Start

### Install

```bash
pip install agent-failsafe
```

### Govern agent code generation

```python
from agent_failsafe import LocalFailSafeClient, FailSafeInterceptor

# Client backed by YAML risk policies and hash-chained SQLite ledger
client = LocalFailSafeClient(
    config_dir=".failsafe/config",
    ledger_path=".failsafe/ledger/soa_ledger.db",
)

# Intercept every file write, code generation, and deployment action
interceptor = FailSafeInterceptor(client, agent_did="did:myth:scrivener:abc123")

# Agent writes a README -> L1, auto-approved
# Agent modifies auth logic -> L3, denied, sandboxed, recorded in ledger
```

### Track development failure rates

```python
from agent_failsafe import FailSafeBridge, FailSafeEvent

bridge = FailSafeBridge()

# Sentinel blocks an agent's attempt to modify credential handling
signal = bridge.process_event(FailSafeEvent(
    event_type="sentinel.verdict",
    agent_did="did:myth:scrivener:abc123",
    details={"decision": "BLOCK", "risk_grade": "L3"},
))

# What fraction of this agent's code generations are passing governance?
bridge.compliance_sli.current_value()   # compliance rate
bridge.escalation_sli.current_value()   # L3 escalation rate
```

### Map development track record to trust

```python
from agent_failsafe import FailSafeTrustMapper, GovernanceDecision

mapper = FailSafeTrustMapper()

# Translate agent DID across governance boundaries
# did:myth:scrivener:abc123 -> did:mesh:abc123
mesh_did = mapper.map_did("did:myth:scrivener:abc123")

# An agent's risk grade reflects its development track record
# L1=900 (trusted), L2=600 (conditional), L3=300 (restricted)
score = mapper.risk_grade_to_trust_score("L2")  # -> 600

# Governance decisions feed back into the trust mesh as reward signals
decision = GovernanceDecision(
    allowed=True, risk_grade="L1", reason="Auto-approved (README edit)", nonce="n1",
)
signal = mapper.decision_to_reward_signal(decision)
```

### Sandbox high-risk code generation

```python
from agent_failsafe import FailSafeRingAdapter

adapter = FailSafeRingAdapter()

# Agent generating crypto code -> RING_3_SANDBOX (isolated execution)
# Agent generating documentation -> RING_2_STANDARD (normal execution)
ring = adapter.risk_grade_to_ring("L3")

# 3+ denied code generations in an hour -> RING_BREACH kill-switch
# Agent under QUARANTINE -> BEHAVIORAL_DRIFT kill-switch
kill_reason = adapter.should_kill(decision)
```

---

## Risk Grading

Every development action an agent takes is classified by the *nature of the code it touches*, not by the agent's permissions or reputation:

| Grade | Meaning | Trust Score | Execution Ring | Policy |
|-------|---------|------------|----------------|--------|
| **L1** | Low risk (docs, config, README) | 900 | RING_2_STANDARD | Auto-approved |
| **L2** | Moderate risk (business logic, tests) | 600 | RING_2_STANDARD | Allowed with conditions |
| **L3** | High risk (auth, crypto, payments, migrations) | 300 | RING_3_SANDBOX | Denied — requires human approval |

**L3 triggers** (configurable via `risk_grading.yaml`): auth, login, password, payment, crypto, migration, admin, secret, credential, token, private_key, api_key.

**Kill-switch escalation**: A `QUARANTINE` condition triggers `BEHAVIORAL_DRIFT`. Three or more L3 denials within a configurable window (default: 1 hour) triggers `RING_BREACH`. Both feed the Shadow Genome.

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │    Autonomous Agent SDLC     │
                    │  Code gen · Architecture ·   │
                    │  Testing · Deployment        │
                    └──────────────┬──────────────┘
                                   │ every dev action
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
 ┌──────────────┐         ┌───────────────┐          ┌──────────────┐
 │   Toolkit    │         │  FailSafe     │          │  Shadow      │
 │              │         │               │          │  Genome      │
 │ "Is this     │         │ "Is what this │          │              │
 │  agent       │         │  agent is     │          │ Failure DNA  │
 │  allowed?"   │         │  building     │          │ for the next │
 │              │         │  safe?"       │          │ iteration    │
 │ Permissions  │         │ Risk grading  │          │              │
 │ Identity     │◄───────►│ Ledger        │─────────►│ What failed  │
 │ Reputation   │         │ SLIs          │          │ Why          │
 │ Health       │         │ Sandboxing    │          │ What to try  │
 └──────────────┘         └───────────────┘          └──────────────┘
```

---

## Modules

| Module | Lines | Exports | Purpose |
|--------|-------|---------|---------|
| `types.py` | 57 | `GovernanceDecision`, `GovernanceEventLog` | Frozen decision dataclass and event log Protocol |
| `client.py` | 202 | `LocalFailSafeClient` | YAML risk policies + hash-chained SQLite ledger |
| `interceptor.py` | 126 | `FailSafeClient`, `FailSafeInterceptor`, `FailSafeIntegration` | Agent OS interceptor chain + lifecycle integration |
| `bridge.py` | 196 | `FailSafeBridge`, `FailSafeEvent` | FailSafe events to SRE signals + SLI management |
| `sli.py` | 111 | `FailSafeComplianceSLI`, `EscalationRateSLI` | Compliance rate and L3 escalation rate indicators |
| `trust_mapper.py` | 139 | `FailSafeTrustMapper` | DID translation + risk-to-trust + reward signals |
| `ring_adapter.py` | 82 | `FailSafeRingAdapter` | Risk grade to execution ring + kill-switch logic |

**952 lines** across 8 source files. **61 tests**, all passing.

---

## Core Types

### GovernanceDecision

Immutable (frozen) dataclass — the single source of truth for all modules:

```python
@dataclass(frozen=True)
class GovernanceDecision:
    allowed: bool
    risk_grade: str       # L1, L2, or L3
    reason: str
    nonce: str            # Unique per evaluation
    conditions: list[str] # e.g., ["requires_human_review", "QUARANTINE"]
    ledger_entry_id: str  # Hash-chained SQLite row
    trace_id: str         # Distributed tracing correlation
```

### GovernanceEventLog Protocol

Structural typing Protocol compatible with `agentmesh.governance.audit.AuditLog` — no cross-package import required:

```python
class GovernanceEventLog(Protocol):
    def log(self, event_type, agent_did, action, ...) -> Any: ...
    def query(self, agent_did, event_type, start_time, ...) -> Sequence[Any]: ...
```

---

## The Agent Governance Ecosystem

```
agent-compliance ─── Unified installer (pip install ai-agent-compliance[full])
├── agent-os-kernel ─── Policy engine: "is this agent allowed?"
├── agentmesh-platform ─── Trust mesh: "is this agent who it claims to be?"
├── agent-hypervisor ─── Execution isolation: "how much rope does this agent get?"
├── agent-sre ─── Reliability: "is the system healthy?"
└── agent-failsafe ─── SDLC governance: "is what this agent is building safe?"
```

Five questions. Five packages. Each answers a different one.

---

## Development

```bash
# Install for development
cd packages/agent-failsafe && pip install -e ".[dev]"

# Run tests
pytest tests/ -x -q --tb=short

# Lint
ruff check src/ --select E,F,W --ignore E501
```

---

## Contributing

We welcome contributions. See the [Contributing Guide](../../CONTRIBUTING.md) for details.

This project follows the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## License

MIT — see [LICENSE](../../LICENSE) for details.

---

<div align="center">

**[github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)** · **[Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)** · **[PyPI](https://pypi.org/project/agent-failsafe/)**

*If you build an agent only to succeed, you neglect to give it a way to safely fail.*

</div>
