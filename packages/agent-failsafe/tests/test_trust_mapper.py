# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for FailSafe trust mapper."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import pytest

from agentmesh.identity.agent_id import AgentDID
from agentmesh.reward.scoring import DimensionType

from agent_failsafe.trust_mapper import FailSafeTrustMapper
from agent_failsafe.types import GovernanceDecision


# --- Fake audit log for persistence tests ---


@dataclass
class _FakeAuditEntry:
    """Minimal entry returned by the fake audit log."""

    event_type: str
    agent_did: str
    action: str
    resource: Optional[str] = None
    outcome: str = "success"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


class _FakeAuditLog:
    """In-memory audit log satisfying the structural interface."""

    def __init__(self) -> None:
        self._entries: list[_FakeAuditEntry] = []

    def log(
        self,
        event_type: str,
        agent_did: str,
        action: str,
        resource: str | None = None,
        data: dict | None = None,
        outcome: str = "success",
        policy_decision: str | None = None,
        trace_id: str | None = None,
    ) -> _FakeAuditEntry:
        entry = _FakeAuditEntry(
            event_type=event_type,
            agent_did=agent_did,
            action=action,
            resource=resource,
            outcome=outcome,
            data=data or {},
        )
        self._entries.append(entry)
        return entry


# --- Risk grade to trust score ---


class TestRiskGradeToTrustScore:
    def test_l1_maps_to_900(self) -> None:
        mapper = FailSafeTrustMapper()
        assert mapper.risk_grade_to_trust_score("L1") == 900

    def test_l3_maps_to_300(self) -> None:
        mapper = FailSafeTrustMapper()
        assert mapper.risk_grade_to_trust_score("L3") == 300

    def test_unknown_grade_maps_to_500(self) -> None:
        mapper = FailSafeTrustMapper()
        assert mapper.risk_grade_to_trust_score("L99") == 500


# --- DID mapping ---


class TestMapDid:
    def test_map_did_myth_to_mesh(self) -> None:
        mapper = FailSafeTrustMapper()
        result = mapper.map_did("did:myth:scrivener:abc123")
        assert isinstance(result, AgentDID)
        assert result.unique_id == "abc123"
        assert str(result) == "did:mesh:abc123"

    def test_map_did_rejects_non_myth(self) -> None:
        mapper = FailSafeTrustMapper()
        with pytest.raises(ValueError, match="Expected did:myth:"):
            mapper.map_did("did:web:foo")


# --- Persona extraction ---


class TestExtractPersona:
    def test_extract_persona(self) -> None:
        mapper = FailSafeTrustMapper()
        assert mapper.extract_persona("did:myth:scrivener:abc123") == "scrivener"


# --- Decision to reward signal ---


class TestDecisionToRewardSignal:
    def test_allowed_decision_reward(self) -> None:
        mapper = FailSafeTrustMapper()
        decision = GovernanceDecision(
            allowed=True,
            risk_grade="L1",
            reason="policy passed",
            nonce="n1",
        )
        signal = mapper.decision_to_reward_signal(decision)
        assert signal.dimension == DimensionType.POLICY_COMPLIANCE
        assert signal.value == 1.0
        assert "allowed" in (signal.details or "")

    def test_denied_decision_reward(self) -> None:
        mapper = FailSafeTrustMapper()
        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="high risk",
            nonce="n2",
        )
        signal = mapper.decision_to_reward_signal(decision)
        assert signal.dimension == DimensionType.POLICY_COMPLIANCE
        assert signal.value == 0.0
        assert "denied" in (signal.details or "")


# --- Security signal ---


class TestRiskGradeToSecuritySignal:
    def test_l3_security_signal(self) -> None:
        mapper = FailSafeTrustMapper()
        signal = mapper.risk_grade_to_security_signal("L3")
        assert signal.dimension == DimensionType.SECURITY_POSTURE
        assert signal.value == pytest.approx(0.2)
        assert "L3" in (signal.details or "")


# --- Audit log integration tests ---


class TestAuditLogIntegration:
    def test_map_did_logs_audit_entry(self) -> None:
        log = _FakeAuditLog()
        mapper = FailSafeTrustMapper(audit_log=log)
        mapper.map_did("did:myth:scrivener:abc123")

        assert len(log._entries) == 1
        entry = log._entries[0]
        assert entry.event_type == "did_mapping"
        assert entry.action == "map_did"
        assert entry.resource == "did:myth:scrivener:abc123"
        assert entry.outcome == "mapped"
        assert entry.data["persona"] == "scrivener"

    def test_decision_to_reward_logs_audit(self) -> None:
        log = _FakeAuditLog()
        mapper = FailSafeTrustMapper(audit_log=log)
        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="high risk",
            nonce="n1",
        )
        mapper.decision_to_reward_signal(decision)

        assert len(log._entries) == 1
        entry = log._entries[0]
        assert entry.event_type == "trust_signal"
        assert entry.action == "decision_to_reward"
        assert entry.resource == "n1"
        assert entry.outcome == "denied"
        assert entry.data["risk_grade"] == "L3"

    def test_allowed_decision_logged_as_allowed(self) -> None:
        log = _FakeAuditLog()
        mapper = FailSafeTrustMapper(audit_log=log)
        decision = GovernanceDecision(
            allowed=True,
            risk_grade="L1",
            reason="ok",
            nonce="n2",
        )
        mapper.decision_to_reward_signal(decision)

        assert log._entries[0].outcome == "allowed"

    def test_mapper_works_without_audit_log(self) -> None:
        mapper = FailSafeTrustMapper()
        result = mapper.map_did("did:myth:sentinel:def456")
        assert result.unique_id == "def456"

    def test_multiple_operations_produce_separate_entries(self) -> None:
        log = _FakeAuditLog()
        mapper = FailSafeTrustMapper(audit_log=log)
        mapper.map_did("did:myth:scrivener:abc123")
        mapper.map_did("did:myth:sentinel:def456")

        assert len(log._entries) == 2
        assert log._entries[0].data["persona"] == "scrivener"
        assert log._entries[1].data["persona"] == "sentinel"
