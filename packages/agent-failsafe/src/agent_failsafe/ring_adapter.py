# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Maps FailSafe risk grades to Hypervisor execution rings and kill decisions.

Kill-switch state is derived from a ``GovernanceEventLog`` (structurally
compatible with ``agentmesh.governance.audit.AuditLog``) so that the L3
denial threshold persists across restarts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypervisor.models import ExecutionRing
from hypervisor.security.kill_switch import KillReason

from agent_failsafe.types import GovernanceDecision, GovernanceEventLog


class FailSafeRingAdapter:
    """Maps FailSafe risk grades to Hypervisor execution rings.

    L3 (high-risk) operations are confined to RING_3_SANDBOX.
    All other risk grades run in RING_2_STANDARD.
    Repeated L3 denials or quarantine conditions trigger kill-switch escalation.

    When an ``event_log`` is provided, the L3 denial count is derived from
    persisted events rather than a caller-supplied parameter.
    """

    def __init__(
        self,
        event_log: GovernanceEventLog | None = None,
        denial_window_seconds: float = 3600.0,
    ) -> None:
        self._event_log = event_log
        self._denial_window = denial_window_seconds

    def risk_grade_to_ring(self, risk_grade: str) -> ExecutionRing:
        """Map a FailSafe risk grade to a Hypervisor execution ring.

        Args:
            risk_grade: FailSafe risk grade (L1, L2, L3).

        Returns:
            ExecutionRing.RING_3_SANDBOX for L3, RING_2_STANDARD otherwise.
        """
        if risk_grade == "L3":
            return ExecutionRing.RING_3_SANDBOX
        return ExecutionRing.RING_2_STANDARD

    def should_kill(self, decision: GovernanceDecision) -> KillReason | None:
        """Determine whether a governance decision warrants a kill-switch.

        Args:
            decision: The FailSafe governance decision.

        Returns:
            A KillReason if the agent should be killed, or None.
        """
        if "QUARANTINE" in decision.conditions:
            return KillReason.BEHAVIORAL_DRIFT
        if not decision.allowed and decision.risk_grade == "L3":
            if self._count_recent_l3_denials() >= 3:
                return KillReason.RING_BREACH
        return None

    def _count_recent_l3_denials(self) -> int:
        """Query the event log for recent L3 denial count."""
        if self._event_log is None:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=self._denial_window,
        )
        entries = self._event_log.query(
            outcome="denied",
            start_time=cutoff,
        )
        return sum(
            1 for e in entries
            if getattr(e, "policy_decision", "") == "L3"
        )
