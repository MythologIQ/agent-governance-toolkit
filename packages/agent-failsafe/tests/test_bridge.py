# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for the FailSafe governance bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import pytest

from agent_sre.incidents.detector import Signal, SignalType

from agent_failsafe.bridge import FailSafeBridge, FailSafeEvent
from agent_failsafe.sli import EscalationRateSLI, FailSafeComplianceSLI


# --- In-memory GovernanceEventLog for tests ---


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
    ) -> _FakeEntry:
        entry = _FakeEntry(
            event_type=event_type,
            agent_did=agent_did,
            action=action,
            outcome=outcome,
            policy_decision=policy_decision,
            data=data or {},
        )
        self._entries.append(entry)
        return entry

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


# --- Test helpers ---


def _sentinel_event(
    decision: str,
    agent_did: str = "did:web:agent-1",
    risk_grade: str = "L1",
) -> FailSafeEvent:
    return FailSafeEvent(
        event_type="sentinel.verdict",
        agent_did=agent_did,
        details={"decision": decision, "risk_grade": risk_grade},
        timestamp=1000.0,
    )


def _l3_event(
    approved: bool,
    agent_did: str = "did:web:agent-2",
) -> FailSafeEvent:
    return FailSafeEvent(
        event_type="qorelogic.l3Decided",
        agent_did=agent_did,
        details={"approved": approved},
        timestamp=1000.0,
    )


# --- Sentinel verdict tests ---


class TestSentinelVerdict:
    def test_sentinel_block_emits_violation(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_sentinel_event("BLOCK"))
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION
        assert "BLOCK" in signal.message
        assert signal.source == "did:web:agent-1"

    def test_sentinel_pass_no_signal(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_sentinel_event("PASS"))
        assert signal is None

    def test_sentinel_quarantine_emits_violation(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_sentinel_event("QUARANTINE"))
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION
        assert "QUARANTINE" in signal.message


# --- L3 decision tests ---


class TestL3Decision:
    def test_l3_rejected_emits_violation(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_l3_event(approved=False))
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION
        assert "rejected" in signal.message

    def test_l3_approved_no_signal(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_l3_event(approved=True))
        assert signal is None


# --- Break-glass tests ---


class TestBreakGlass:
    def test_break_glass_emits_trust_revocation(self) -> None:
        bridge = FailSafeBridge()
        event = FailSafeEvent(
            event_type="governance.breakGlassActivated",
            agent_did="did:web:agent-3",
            details={"reason": "emergency"},
            timestamp=1000.0,
        )
        signal = bridge.process_event(event)
        assert signal is not None
        assert signal.signal_type == SignalType.TRUST_REVOCATION
        assert signal.source == "did:web:agent-3"


# --- Unhandled event types ---


class TestUnhandledEvents:
    def test_ledger_entry_no_signal(self) -> None:
        bridge = FailSafeBridge()
        event = FailSafeEvent(
            event_type="qorelogic.ledgerEntry",
            agent_did="did:web:agent-4",
            details={"entry": "some ledger data"},
            timestamp=1000.0,
        )
        signal = bridge.process_event(event)
        assert signal is None


# --- SLI tracking tests (in-memory fallback, no event log) ---


class TestSLITracking:
    def test_compliance_ratio(self) -> None:
        bridge = FailSafeBridge()
        for _ in range(7):
            bridge.process_event(_sentinel_event("PASS"))
        for _ in range(3):
            bridge.process_event(_sentinel_event("BLOCK"))

        result = bridge.compliance_sli.collect()
        assert abs(result.value - 0.7) < 0.01

    def test_compliance_empty_returns_1(self) -> None:
        sli = FailSafeComplianceSLI()
        result = sli.collect()
        assert result.value == 1.0

    def test_escalation_tracking(self) -> None:
        bridge = FailSafeBridge()
        for _ in range(2):
            bridge.process_event(_sentinel_event("PASS", risk_grade="L3"))
        for _ in range(8):
            bridge.process_event(_sentinel_event("PASS", risk_grade="L1"))

        result = bridge.escalation_sli.collect()
        assert abs(result.value - 0.2) < 0.01


# --- Summary tests (in-memory fallback) ---


class TestSummary:
    def test_summary_counts(self) -> None:
        bridge = FailSafeBridge()
        bridge.process_event(_sentinel_event("PASS"))
        bridge.process_event(_sentinel_event("BLOCK"))
        bridge.process_event(_l3_event(approved=True))

        summary = bridge.summary()
        assert summary["events_processed"] == 3
        assert summary["events_by_type"]["sentinel.verdict"] == 2
        assert summary["events_by_type"]["qorelogic.l3Decided"] == 1


# --- Event log persistence tests ---


class TestEventLogPersistence:
    def test_process_event_logs_to_event_log(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        bridge.process_event(_sentinel_event("BLOCK", risk_grade="L2"))

        assert len(log._entries) == 1
        entry = log._entries[0]
        assert entry.event_type == "sentinel.verdict"
        assert entry.outcome == "denied"
        assert entry.policy_decision == "L2"

    def test_sentinel_pass_logged_as_success(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        bridge.process_event(_sentinel_event("PASS"))

        assert log._entries[0].outcome == "success"

    def test_l3_approved_logged_as_success(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        bridge.process_event(_l3_event(approved=True))

        assert log._entries[0].outcome == "success"

    def test_l3_rejected_logged_as_denied(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        bridge.process_event(_l3_event(approved=False))

        assert log._entries[0].outcome == "denied"

    def test_break_glass_logged_as_denied(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        event = FailSafeEvent(
            event_type="governance.breakGlassActivated",
            agent_did="did:web:agent-3",
            details={"reason": "emergency"},
            timestamp=1000.0,
        )
        bridge.process_event(event)
        assert log._entries[0].outcome == "denied"

    def test_bridge_works_without_event_log(self) -> None:
        bridge = FailSafeBridge()
        signal = bridge.process_event(_sentinel_event("BLOCK"))
        assert signal is not None
        assert signal.signal_type == SignalType.POLICY_VIOLATION

    def test_classify_outcome_all_types(self) -> None:
        assert FailSafeBridge._classify_outcome(
            _sentinel_event("BLOCK"),
        ) == "denied"
        assert FailSafeBridge._classify_outcome(
            _sentinel_event("PASS"),
        ) == "success"
        assert FailSafeBridge._classify_outcome(
            _l3_event(approved=True),
        ) == "success"
        assert FailSafeBridge._classify_outcome(
            _l3_event(approved=False),
        ) == "denied"
        assert FailSafeBridge._classify_outcome(FailSafeEvent(
            event_type="governance.breakGlassActivated",
            agent_did="x",
        )) == "denied"
        assert FailSafeBridge._classify_outcome(FailSafeEvent(
            event_type="unknown.event",
            agent_did="x",
        )) == "success"


# --- SLI derivation from event log ---


class TestSLIDerivedFromEventLog:
    def test_compliance_sli_derives_from_event_log(self) -> None:
        log = _FakeEventLog()
        for _ in range(6):
            log.log("sentinel.verdict", "a1", "eval", outcome="success")
        for _ in range(4):
            log.log("sentinel.verdict", "a1", "eval", outcome="denied")

        sli = FailSafeComplianceSLI(event_log=log)
        result = sli.collect()
        assert abs(result.value - 0.6) < 0.01

    def test_escalation_sli_derives_from_event_log(self) -> None:
        log = _FakeEventLog()
        for _ in range(3):
            log.log("sentinel.verdict", "a1", "eval", policy_decision="L3")
        for _ in range(7):
            log.log("sentinel.verdict", "a1", "eval", policy_decision="L1")

        sli = EscalationRateSLI(event_log=log)
        result = sli.collect()
        assert abs(result.value - 0.3) < 0.01

    def test_escalation_empty_log_returns_0(self) -> None:
        log = _FakeEventLog()
        sli = EscalationRateSLI(event_log=log)
        result = sli.collect()
        assert result.value == 0.0

    def test_compliance_empty_log_returns_1(self) -> None:
        log = _FakeEventLog()
        sli = FailSafeComplianceSLI(event_log=log)
        result = sli.collect()
        assert result.value == 1.0


# --- Summary from event log ---


class TestSummaryFromEventLog:
    def test_summary_groups_by_event_type(self) -> None:
        log = _FakeEventLog()
        bridge = FailSafeBridge(event_log=log)
        bridge.process_event(_sentinel_event("PASS"))
        bridge.process_event(_sentinel_event("BLOCK"))
        bridge.process_event(_l3_event(approved=True))
        bridge.process_event(FailSafeEvent(
            event_type="governance.breakGlassActivated",
            agent_did="did:web:agent-3",
            details={},
            timestamp=1000.0,
        ))

        summary = bridge.summary()
        assert summary["events_processed"] == 4
        assert summary["events_by_type"]["sentinel.verdict"] == 2
        assert summary["events_by_type"]["qorelogic.l3Decided"] == 1
        assert summary["events_by_type"]["governance.breakGlassActivated"] == 1
