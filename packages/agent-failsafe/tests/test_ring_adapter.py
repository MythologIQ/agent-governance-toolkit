# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for FailSafe ring adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from hypervisor.models import ExecutionRing
from hypervisor.security.kill_switch import KillReason

from agent_failsafe.ring_adapter import FailSafeRingAdapter
from agent_failsafe.types import GovernanceDecision


# --- Fake event log for persistence tests ---


@dataclass
class _FakeEntry:
    """Minimal entry returned by the fake event log."""

    event_type: str
    agent_did: str
    action: str
    outcome: str = "success"
    policy_decision: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


class _FakeEventLog:
    """In-memory GovernanceEventLog satisfying the Protocol structurally."""

    def __init__(self) -> None:
        self._entries: list[_FakeEntry] = []

    def query(
        self,
        agent_did: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        outcome: str | None = None,
        limit: int = 100,
    ) -> list[_FakeEntry]:
        results = list(self._entries)
        if agent_did:
            results = [e for e in results if e.agent_did == agent_did]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        if outcome:
            results = [e for e in results if e.outcome == outcome]
        return results[-limit:]

    def add(
        self,
        outcome: str = "denied",
        policy_decision: str = "L3",
        age_seconds: float = 0.0,
    ) -> None:
        """Helper to add a pre-dated entry."""
        ts = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        self._entries.append(
            _FakeEntry(
                event_type="sentinel.verdict",
                agent_did="did:web:agent-1",
                action="eval",
                outcome=outcome,
                policy_decision=policy_decision,
                timestamp=ts,
            )
        )


# --- Risk grade to ring tests ---


class TestRiskGradeToRing:
    def test_l3_maps_to_sandbox(self) -> None:
        adapter = FailSafeRingAdapter()
        assert adapter.risk_grade_to_ring("L3") == ExecutionRing.RING_3_SANDBOX

    def test_l1_maps_to_standard(self) -> None:
        adapter = FailSafeRingAdapter()
        assert adapter.risk_grade_to_ring("L1") == ExecutionRing.RING_2_STANDARD

    def test_l2_maps_to_standard(self) -> None:
        adapter = FailSafeRingAdapter()
        assert adapter.risk_grade_to_ring("L2") == ExecutionRing.RING_2_STANDARD


# --- Should-kill tests (no event log) ---


class TestShouldKillNoEventLog:
    def test_quarantine_triggers_drift_kill(self) -> None:
        adapter = FailSafeRingAdapter()
        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L2",
            reason="quarantined",
            nonce="n2",
            conditions=("QUARANTINE",),
        )
        assert adapter.should_kill(decision) == KillReason.BEHAVIORAL_DRIFT

    def test_l3_denial_without_event_log_no_kill(self) -> None:
        """Without an event log, _count_recent_l3_denials returns 0."""
        adapter = FailSafeRingAdapter()
        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) is None

    def test_allowed_decision_no_kill(self) -> None:
        adapter = FailSafeRingAdapter()
        decision = GovernanceDecision(
            allowed=True,
            risk_grade="L1",
            reason="ok",
            nonce="n3",
        )
        assert adapter.should_kill(decision) is None


# --- Should-kill tests (with event log) ---


class TestShouldKillWithEventLog:
    def test_three_recent_l3_denials_triggers_kill(self) -> None:
        log = _FakeEventLog()
        for _ in range(3):
            log.add(outcome="denied", policy_decision="L3")
        adapter = FailSafeRingAdapter(event_log=log)

        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="repeated violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) == KillReason.RING_BREACH

    def test_two_l3_denials_no_kill(self) -> None:
        log = _FakeEventLog()
        for _ in range(2):
            log.add(outcome="denied", policy_decision="L3")
        adapter = FailSafeRingAdapter(event_log=log)

        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) is None

    def test_old_denials_outside_window_ignored(self) -> None:
        log = _FakeEventLog()
        for _ in range(5):
            log.add(outcome="denied", policy_decision="L3", age_seconds=7200)
        adapter = FailSafeRingAdapter(event_log=log)

        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) is None

    def test_non_l3_denials_not_counted(self) -> None:
        log = _FakeEventLog()
        for _ in range(5):
            log.add(outcome="denied", policy_decision="L1")
        adapter = FailSafeRingAdapter(event_log=log)

        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) is None

    def test_custom_denial_window(self) -> None:
        log = _FakeEventLog()
        for _ in range(3):
            log.add(outcome="denied", policy_decision="L3", age_seconds=1800)

        adapter = FailSafeRingAdapter(event_log=log, denial_window_seconds=600)
        decision = GovernanceDecision(
            allowed=False,
            risk_grade="L3",
            reason="violation",
            nonce="n1",
        )
        assert adapter.should_kill(decision) is None
