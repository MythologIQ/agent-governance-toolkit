# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""FailSafe SLIs — compliance rate and L3 escalation rate.

When a ``GovernanceEventLog`` is provided, ``collect()`` derives metrics
from persisted events.  Otherwise falls back to in-memory measurements.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from agent_sre.slo.indicators import SLI, SLIValue, TimeWindow

if TYPE_CHECKING:
    from agent_failsafe.types import GovernanceEventLog


_BLOCKING_DECISIONS = frozenset({"BLOCK", "QUARANTINE", "ESCALATE"})


class FailSafeComplianceSLI(SLI):
    """Tracks the fraction of FailSafe decisions that are compliant (allowed).

    When an ``event_log`` is provided, ``collect()`` derives the compliance
    rate from persisted events.  Otherwise it falls back to in-memory
    measurements recorded via ``record_decision()``.
    """

    def __init__(
        self,
        target: float = 0.95,
        window: TimeWindow | str = "24h",
        event_log: GovernanceEventLog | None = None,
    ) -> None:
        super().__init__("failsafe_compliance", target, window)
        self._event_log = event_log

    def record_decision(
        self,
        allowed: bool,
        risk_grade: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> SLIValue:
        """Record a single governance decision."""
        value = 1.0 if allowed else 0.0
        return self.record(value, {"risk_grade": risk_grade, **(metadata or {})})

    def collect(self) -> SLIValue:
        """Collect the current compliance rate."""
        if self._event_log is None:
            return self._collect_from_measurements()
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window.seconds)
        entries = self._event_log.query(start_time=cutoff)
        if not entries:
            return self.record(1.0)
        compliant = sum(
            1 for e in entries if getattr(e, "outcome", "") != "denied"
        )
        return self.record(compliant / len(entries))

    def _collect_from_measurements(self) -> SLIValue:
        """Fallback: derive from in-memory SLI measurements."""
        vals = self.values_in_window()
        if not vals:
            return self.record(1.0)
        return self.record(sum(v.value for v in vals) / len(vals))


class EscalationRateSLI(SLI):
    """Tracks the fraction of decisions escalated to L3 risk grade.

    Lower is better — a high escalation rate may indicate overly aggressive
    risk grading or an increase in genuinely risky operations.
    """

    def __init__(
        self,
        target: float = 0.1,
        window: TimeWindow | str = "24h",
        event_log: GovernanceEventLog | None = None,
    ) -> None:
        super().__init__("failsafe_escalation_rate", target, window)
        self._event_log = event_log

    def record_risk_grade(self, risk_grade: str) -> SLIValue:
        """Record a risk grade observation."""
        value = 1.0 if risk_grade.upper() == "L3" else 0.0
        return self.record(value, {"risk_grade": risk_grade})

    def collect(self) -> SLIValue:
        """Collect the current escalation rate."""
        if self._event_log is None:
            return self._collect_from_measurements()
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window.seconds)
        entries = self._event_log.query(start_time=cutoff)
        if not entries:
            return self.record(0.0)
        l3 = sum(
            1 for e in entries
            if getattr(e, "policy_decision", "") == "L3"
        )
        return self.record(l3 / len(entries))

    def _collect_from_measurements(self) -> SLIValue:
        """Fallback: derive from in-memory SLI measurements."""
        vals = self.values_in_window()
        if not vals:
            return self.record(0.0)
        return self.record(sum(v.value for v in vals) / len(vals))
