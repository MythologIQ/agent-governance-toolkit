# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Maps FailSafe governance state to AgentMesh trust signals.

When an ``audit_log`` is provided, DID mappings and trust signal
conversions are recorded as hash-chained audit entries for tamper-evident
traceability.
"""

from __future__ import annotations

from typing import Any

from agentmesh.identity.agent_id import AgentDID
from agentmesh.reward.scoring import DimensionType, RewardSignal

from agent_failsafe.trust import TrustStage, apply_outcome, determine_stage
from agent_failsafe.types import GovernanceDecision


class FailSafeTrustMapper:
    """Maps FailSafe governance state to AgentMesh trust signals.

    Translates FailSafe DIDs, risk grades, and governance decisions into
    AgentMesh-native trust primitives (AgentDID, RewardSignal, trust scores).
    """

    RISK_GRADE_TRUST: dict[str, int] = {"L1": 900, "L2": 600, "L3": 300}

    def __init__(self, audit_log: Any = None) -> None:
        self._audit_log = audit_log

    def risk_grade_to_trust_score(self, risk_grade: str) -> int:
        """Convert a FailSafe risk grade to a numeric trust score (0-1000).

        Args:
            risk_grade: FailSafe risk grade (L1, L2, L3).

        Returns:
            Trust score integer. Unknown grades default to 500.
        """
        return self.RISK_GRADE_TRUST.get(risk_grade, 500)

    def map_did(self, failsafe_did: str) -> AgentDID:
        """Map a FailSafe DID to an AgentMesh DID.

        Converts ``did:myth:{persona}:{hash}`` to ``did:mesh:{hash}``.

        Args:
            failsafe_did: A FailSafe DID string in ``did:myth:`` format.

        Returns:
            An AgentDID with the hash portion as unique_id.

        Raises:
            ValueError: If the DID is not in valid ``did:myth:`` format.
        """
        if not failsafe_did.startswith("did:myth:"):
            raise ValueError(f"Expected did:myth: DID, got: {failsafe_did}")
        parts = failsafe_did.split(":")
        if len(parts) != 4:
            raise ValueError(f"Invalid FailSafe DID format: {failsafe_did}")
        result = AgentDID(unique_id=parts[3])
        if self._audit_log is not None:
            self._audit_log.log(
                event_type="did_mapping",
                agent_did=str(result),
                action="map_did",
                resource=failsafe_did,
                outcome="mapped",
                data={"persona": parts[2]},
            )
        return result

    def extract_persona(self, failsafe_did: str) -> str:
        """Extract the persona segment from a FailSafe DID.

        Args:
            failsafe_did: A FailSafe DID string.

        Returns:
            The persona name, or ``"unknown"`` if not parseable.
        """
        parts = failsafe_did.split(":")
        return parts[2] if len(parts) >= 3 else "unknown"

    def decision_to_reward_signal(
        self,
        decision: GovernanceDecision,
        source: str = "failsafe",
    ) -> RewardSignal:
        """Convert a governance decision to a policy-compliance reward signal.

        Args:
            decision: The FailSafe governance decision.
            source: Signal source identifier.

        Returns:
            A RewardSignal on the POLICY_COMPLIANCE dimension.
        """
        value = 1.0 if decision.allowed else 0.0
        details = f"FailSafe {'allowed' if decision.allowed else 'denied'}: {decision.reason}"
        signal = RewardSignal(
            dimension=DimensionType.POLICY_COMPLIANCE,
            value=value,
            source=source,
            details=details,
        )
        if self._audit_log is not None:
            self._audit_log.log(
                event_type="trust_signal",
                agent_did=source,
                action="decision_to_reward",
                resource=decision.nonce,
                outcome="allowed" if decision.allowed else "denied",
                data={"risk_grade": decision.risk_grade},
            )
        return signal

    def risk_grade_to_security_signal(
        self,
        risk_grade: str,
        source: str = "failsafe",
    ) -> RewardSignal:
        """Convert a risk grade to a security-posture reward signal.

        Args:
            risk_grade: FailSafe risk grade (L1, L2, L3).
            source: Signal source identifier.

        Returns:
            A RewardSignal on the SECURITY_POSTURE dimension.
        """
        value_map: dict[str, float] = {"L1": 0.9, "L2": 0.5, "L3": 0.2}
        return RewardSignal(
            dimension=DimensionType.SECURITY_POSTURE,
            value=value_map.get(risk_grade, 0.5),
            source=source,
            details=f"FailSafe risk grade: {risk_grade}",
        )

    def update_trust(self, current_score: float, decision: GovernanceDecision) -> float:
        """Apply a governance decision to update a trust score dynamically.

        Args:
            current_score: Current trust score (0.0-1.0).
            decision: The FailSafe governance decision.

        Returns:
            Updated trust score, clamped to [0.0, 1.0].
        """
        return apply_outcome(current_score, decision.allowed, decision.risk_grade)

    def get_trust_stage(self, score: float) -> TrustStage:
        """Determine the trust stage for a given score.

        Args:
            score: Trust score (0.0-1.0).

        Returns:
            The corresponding ``TrustStage``.
        """
        return determine_stage(score)
