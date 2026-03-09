# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for FailSafe interceptor, integration, and client."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
import yaml

from agent_failsafe.client import LocalFailSafeClient
from agent_failsafe.interceptor import (
    FailSafeIntegration,
    FailSafeInterceptor,
)
from agent_failsafe.types import GovernanceDecision
from agent_os.integrations.base import (
    CompositeInterceptor,
    GovernanceEventType,
    ToolCallRequest,
    ToolCallResult,
)


# ── Helpers ──────────────────────────────────────────────────


def _make_config(tmp_path):
    """Write a minimal risk_grading.yaml and return the config dir."""
    risk_config = {
        "auto_classification": {
            "file_path_triggers": {"L3": ["auth", "crypto", "payment"]},
            "content_triggers": {"L3": ["private_key", "api_key"]},
        }
    }
    config_dir = tmp_path / "config"
    policies_dir = config_dir / "policies"
    policies_dir.mkdir(parents=True)
    (policies_dir / "risk_grading.yaml").write_text(yaml.dump(risk_config))
    return str(config_dir)


def _make_client(tmp_path):
    """Create a LocalFailSafeClient with tmp dirs."""
    config_dir = _make_config(tmp_path)
    ledger_path = str(tmp_path / "ledger" / "soa_ledger.db")
    return LocalFailSafeClient(config_dir=config_dir, ledger_path=ledger_path)


# ── 1. GovernanceDecision immutability ───────────────────────


def test_governance_decision_frozen():
    d = GovernanceDecision(
        allowed=True, risk_grade="L1", reason="ok", nonce="abc",
    )
    with pytest.raises(FrozenInstanceError):
        d.allowed = False  # type: ignore[misc]


def test_governance_decision_defaults():
    d = GovernanceDecision(
        allowed=True, risk_grade="L1", reason="ok", nonce="abc",
    )
    assert d.conditions == ()
    assert d.ledger_entry_id == ""
    assert d.trace_id == ""


# ── 2. L1 auto-allows ───────────────────────────────────────


def test_l1_auto_allows(tmp_path):
    client = _make_client(tmp_path)
    decision = client.evaluate(
        action="read_file", agent_did="did:test:1",
        context={}, artifact_path="docs/README.md",
    )
    assert decision.allowed is True
    assert decision.risk_grade == "L1"


# ── 3. L3 denies ────────────────────────────────────────────


def test_l3_denies_without_approval(tmp_path):
    client = _make_client(tmp_path)
    decision = client.evaluate(
        action="modify_auth_config", agent_did="did:test:1",
        context={}, artifact_path="src/auth/handler.py",
    )
    assert decision.allowed is False
    assert decision.risk_grade == "L3"


# ── 4. L2 allows with conditions ────────────────────────────


def test_l2_allows_with_conditions(tmp_path):
    client = _make_client(tmp_path)
    decision = client.evaluate(
        action="refactor_utils", agent_did="did:test:1",
        context={}, artifact_path="src/utils/helpers.py",
    )
    assert decision.allowed is True
    assert decision.risk_grade == "L2"
    assert "requires_human_review" in decision.conditions


# ── 5. Ledger append ────────────────────────────────────────


def test_appends_ledger_entry(tmp_path):
    client = _make_client(tmp_path)
    client.evaluate(
        action="read_file", agent_did="did:test:1",
        context={}, artifact_path="docs/changelog.txt",
    )
    entries = client.query_ledger("did:test:1")
    assert len(entries) == 1
    assert entries[0]["agent_did"] == "did:test:1"


# ── 6. Nonce uniqueness ─────────────────────────────────────


def test_nonce_uniqueness(tmp_path):
    client = _make_client(tmp_path)
    d1 = client.evaluate("a", "did:test:1", {})
    d2 = client.evaluate("b", "did:test:1", {})
    assert d1.nonce != d2.nonce


# ── 7. Query ledger by agent ────────────────────────────────


def test_query_ledger_by_agent(tmp_path):
    client = _make_client(tmp_path)
    client.evaluate("a", "did:agent:A", {})
    client.evaluate("b", "did:agent:B", {})
    client.evaluate("c", "did:agent:A", {})
    entries_a = client.query_ledger("did:agent:A")
    entries_b = client.query_ledger("did:agent:B")
    assert len(entries_a) == 2
    assert len(entries_b) == 1


# ── 8. Interceptor deny ─────────────────────────────────────


def test_interceptor_deny_returns_blocked(tmp_path):
    client = _make_client(tmp_path)
    interceptor = FailSafeInterceptor(client, agent_did="did:test:1")
    request = ToolCallRequest(
        tool_name="update_auth_config",
        arguments={},
        metadata={"artifact_path": "src/auth/login.py"},
    )
    result = interceptor.intercept(request)
    assert result.allowed is False
    assert result.audit_entry is not None
    assert result.audit_entry["risk_grade"] == "L3"


# ── 9. Interceptor allow ────────────────────────────────────


def test_interceptor_allow_returns_allowed(tmp_path):
    client = _make_client(tmp_path)
    interceptor = FailSafeInterceptor(client, agent_did="did:test:1")
    request = ToolCallRequest(
        tool_name="read_docs",
        arguments={},
        metadata={"artifact_path": "docs/README.md"},
    )
    result = interceptor.intercept(request)
    assert result.allowed is True
    assert result.audit_entry is not None


# ── 10. Composable with CompositeInterceptor ────────────────


def test_interceptor_composable(tmp_path):
    client = _make_client(tmp_path)
    interceptor = FailSafeInterceptor(client, agent_did="did:test:1")

    class AllowAll:
        def intercept(self, request: ToolCallRequest) -> ToolCallResult:
            return ToolCallResult(allowed=True)

    composite = CompositeInterceptor([AllowAll(), interceptor])
    request = ToolCallRequest(
        tool_name="modify_payment_service",
        arguments={},
        metadata={"artifact_path": "src/payment/handler.py"},
    )
    result = composite.intercept(request)
    assert result.allowed is False


# ── 11. Integration emits POLICY_CHECK ───────────────────────


def test_integration_pre_execute_emits_policy_check(tmp_path):
    client = _make_client(tmp_path)
    integration = FailSafeIntegration(client)
    events: list[dict] = []
    integration.on(GovernanceEventType.POLICY_CHECK, events.append)

    ctx = integration.create_context("agent-1")
    allowed, _ = integration.pre_execute(ctx, "read docs/README.md")
    assert allowed is True
    assert len(events) >= 1


# ── 12. Integration emits POLICY_VIOLATION on deny ──────────


def test_integration_denied_emits_violation(tmp_path):
    client = _make_client(tmp_path)
    integration = FailSafeIntegration(client)
    violations: list[dict] = []
    integration.on(GovernanceEventType.POLICY_VIOLATION, violations.append)

    ctx = integration.create_context("agent-2")
    allowed, reason = integration.pre_execute(ctx, "modify auth login handler")
    assert allowed is False
    assert reason is not None
    assert len(violations) == 1
    assert violations[0]["risk_grade"] == "L3"
