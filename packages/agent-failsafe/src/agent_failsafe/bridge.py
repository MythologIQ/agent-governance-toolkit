# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""FailSafe governance bridge — translates FailSafe events into SRE signals.

Connects to FailSafe's governance layer:
- Sentinel verdicts (BLOCK/QUARANTINE/ESCALATE) -> policy violation signals
- L3 risk decisions -> escalation tracking + compliance SLI
- Break-glass activations -> trust revocation signals
- All decisions feed compliance and escalation rate SLIs

Events are persisted to a ``GovernanceEventLog`` (structurally compatible
with ``agentmesh.governance.audit.AuditLog``) so that SLI state survives
restarts and can feed a persistent UI via CloudEvents export.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from agent_sre.incidents.detector import Signal, SignalType
from agent_sre.slo.indicators import SLI

from agent_failsafe.sli import EscalationRateSLI, FailSafeComplianceSLI
from agent_failsafe.types import GovernanceEventLog


# --- Data Transfer Objects ---


@dataclass
class FailSafeEvent:
    """A governance event received from the FailSafe system."""

    event_type: str
    agent_did: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


# --- Constants ---


_BLOCKING_DECISIONS = frozenset({"BLOCK", "QUARANTINE", "ESCALATE"})


# --- Bridge ---


class FailSafeBridge:
    """Translates FailSafe governance events into Agent SRE signals and SLIs.

    When an ``event_log`` is provided, every processed event is persisted
    and SLI state survives restarts.  Without one the bridge falls back to
    transient in-memory tracking (original behaviour).
    """

    def __init__(self, event_log: GovernanceEventLog | None = None) -> None:
        self._event_log = event_log
        self._compliance_sli = FailSafeComplianceSLI(event_log=event_log)
        self._escalation_sli = EscalationRateSLI(event_log=event_log)
        self._events_processed = 0
        self._events_by_type: dict[str, int] = {}

    @property
    def compliance_sli(self) -> FailSafeComplianceSLI:
        """The compliance rate SLI."""
        return self._compliance_sli

    @property
    def escalation_sli(self) -> EscalationRateSLI:
        """The L3 escalation rate SLI."""
        return self._escalation_sli

    def process_event(self, event: FailSafeEvent) -> Signal | None:
        """Process a FailSafe event and optionally emit an SRE signal.

        Returns a ``Signal`` for blocking verdicts, rejected L3 decisions,
        and break-glass activations.  All other events return ``None``.
        """
        self._events_processed += 1
        self._events_by_type[event.event_type] = (
            self._events_by_type.get(event.event_type, 0) + 1
        )

        if self._event_log is not None:
            self._persist_event(event)

        ts = event.timestamp or time.time()

        if event.event_type == "sentinel.verdict":
            return self._handle_sentinel(event, ts)
        if event.event_type == "qorelogic.l3Decided":
            return self._handle_l3_decided(event, ts)
        if event.event_type == "governance.breakGlassActivated":
            return self._handle_break_glass(event, ts)
        return None

    def _persist_event(self, event: FailSafeEvent) -> None:
        """Write a governance event to the audit log."""
        outcome = self._classify_outcome(event)
        self._event_log.log(  # type: ignore[union-attr]
            event_type=event.event_type,
            agent_did=event.agent_did,
            action=event.event_type,
            data=event.details,
            outcome=outcome,
            policy_decision=event.details.get("risk_grade"),
        )

    @staticmethod
    def _classify_outcome(event: FailSafeEvent) -> str:
        """Map event semantics to an outcome string for the audit log."""
        if event.event_type == "sentinel.verdict":
            decision = event.details.get("decision", "").upper()
            return "denied" if decision in _BLOCKING_DECISIONS else "success"
        if event.event_type == "qorelogic.l3Decided":
            return "success" if event.details.get("approved") else "denied"
        if event.event_type == "governance.breakGlassActivated":
            return "denied"
        return "success"

    # -- private handlers --

    def _handle_sentinel(
        self, event: FailSafeEvent, ts: float,
    ) -> Signal | None:
        decision = event.details.get("decision", "").upper()
        risk_grade = event.details.get("risk_grade", "")
        allowed = decision not in _BLOCKING_DECISIONS
        self._compliance_sli.record_decision(allowed, risk_grade)
        self._escalation_sli.record_risk_grade(risk_grade)
        if not allowed:
            return Signal(
                signal_type=SignalType.POLICY_VIOLATION,
                source=event.agent_did,
                message=f"FailSafe sentinel {decision} for {event.agent_did}",
                timestamp=ts,
                metadata=event.details,
            )
        return None

    def _handle_l3_decided(
        self, event: FailSafeEvent, ts: float,
    ) -> Signal | None:
        approved = event.details.get("approved", False)
        self._compliance_sli.record_decision(approved, "L3")
        self._escalation_sli.record_risk_grade("L3")
        if not approved:
            return Signal(
                signal_type=SignalType.POLICY_VIOLATION,
                source=event.agent_did,
                message=f"FailSafe L3 decision rejected for {event.agent_did}",
                timestamp=ts,
                metadata=event.details,
            )
        return None

    def _handle_break_glass(
        self, event: FailSafeEvent, ts: float,
    ) -> Signal:
        self._compliance_sli.record_decision(False, "L3")
        self._escalation_sli.record_risk_grade("L3")
        return Signal(
            signal_type=SignalType.TRUST_REVOCATION,
            source=event.agent_did,
            message=f"Break-glass activated for {event.agent_did}",
            timestamp=ts,
            metadata=event.details,
        )

    def slis(self) -> list[SLI]:
        """Return all SLIs managed by this bridge."""
        return [self._compliance_sli, self._escalation_sli]

    def summary(self) -> dict[str, Any]:
        """Return a summary of bridge activity."""
        if self._event_log is not None:
            entries = self._event_log.query(limit=1000)
            by_type: dict[str, int] = {}
            for e in entries:
                et = getattr(e, "event_type", "unknown")
                by_type[et] = by_type.get(et, 0) + 1
            return {
                "events_processed": len(entries),
                "events_by_type": by_type,
                "compliance": self._compliance_sli.current_value(),
                "escalation_rate": self._escalation_sli.current_value(),
            }
        return {
            "events_processed": self._events_processed,
            "events_by_type": dict(self._events_by_type),
            "compliance": self._compliance_sli.current_value(),
            "escalation_rate": self._escalation_sli.current_value(),
        }
