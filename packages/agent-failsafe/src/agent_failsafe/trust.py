# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Trust dynamics for the FailSafe governance bridge.

Implements a three-stage trust model inspired by organisational trust
theory:

- **CBT (Calculus-Based Trust)** — Initial stage (score 0.0-0.5).
  Trust is fragile, based purely on cost/benefit analysis.  Agents
  start here and must demonstrate reliable behaviour to advance.

- **KBT (Knowledge-Based Trust)** — Intermediate stage (score 0.5-0.8).
  Built from accumulated interaction history.  Agents have a track
  record that informs expectations.

- **IBT (Identification-Based Trust)** — Mature stage (score 0.8-1.0).
  Deep alignment with governance values.  Reserved for agents that
  consistently uphold policy over extended periods.

All functions are pure — no side effects, no state mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TrustStage(str, Enum):
    """Three-stage trust progression model."""

    CBT = "CBT"  # Calculus-Based Trust (0.0-0.5)
    KBT = "KBT"  # Knowledge-Based Trust (0.5-0.8)
    IBT = "IBT"  # Identification-Based Trust (0.8-1.0)


@dataclass(frozen=True)
class TrustConfig:
    """Immutable configuration for trust dynamics.

    All thresholds and deltas are tunable.  The frozen default
    instance ``DEFAULT_TRUST_CONFIG`` covers the common case.
    """

    default_trust: float = 0.35
    success_delta: float = 0.05
    failure_delta: float = -0.10
    violation_penalty: float = -0.25
    probation_floor: float = 0.35
    probation_verifications: int = 5
    probation_days: int = 30
    cbt_max: float = 0.5
    kbt_max: float = 0.8


DEFAULT_TRUST_CONFIG: TrustConfig = TrustConfig()


def determine_stage(
    score: float,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> TrustStage:
    """Determine the trust stage for a given score.

    Args:
        score: Current trust score (0.0-1.0).
        config: Trust configuration to use.

    Returns:
        The corresponding ``TrustStage``.
    """
    if score < config.cbt_max:
        return TrustStage.CBT
    if score < config.kbt_max:
        return TrustStage.KBT
    return TrustStage.IBT


def apply_outcome(
    current_score: float,
    allowed: bool,
    risk_grade: str,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> float:
    """Apply a governance outcome to produce an updated trust score.

    Args:
        current_score: Current trust score (0.0-1.0).
        allowed: Whether the action was allowed.
        risk_grade: FailSafe risk grade (L1, L2, L3).
        config: Trust configuration to use.

    Returns:
        Updated trust score, clamped to [0.0, 1.0].
    """
    if allowed:
        delta = config.success_delta
    elif risk_grade == "L3":
        delta = config.violation_penalty
    else:
        delta = config.failure_delta

    return max(0.0, min(1.0, current_score + delta))


def is_probationary(
    days_active: int,
    verifications_completed: int,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> bool:
    """Check whether an agent is still in probationary status.

    An agent is probationary until it has been active for at least
    ``config.probation_days`` **and** completed at least
    ``config.probation_verifications`` verifications.

    Args:
        days_active: Number of days the agent has been active.
        verifications_completed: Number of completed verifications.
        config: Trust configuration to use.

    Returns:
        ``True`` if still probationary, ``False`` otherwise.
    """
    if days_active < config.probation_days:
        return True
    return verifications_completed < config.probation_verifications


def calculate_influence_weight(
    score: float,
    is_probationary_flag: bool,
    config: TrustConfig = DEFAULT_TRUST_CONFIG,
) -> float:
    """Calculate influence weight for governance voting.

    Probationary agents receive a fixed low weight (0.1).
    Non-probationary agents scale linearly from 0.5 (score=0.0) to
    2.0 (score=1.0).

    Args:
        score: Current trust score (0.0-1.0).
        is_probationary_flag: Whether the agent is probationary.
        config: Trust configuration (reserved for future use).

    Returns:
        Influence weight as a float.
    """
    if is_probationary_flag:
        return 0.1
    return 0.5 + score * 1.5


def score_to_mesh_trust(score: float) -> int:
    """Convert a float trust score to an AgentMesh integer score.

    AgentMesh uses integer scores in the range 0-1000.  This function
    maps a 0.0-1.0 float linearly, clamping out-of-range inputs.

    Args:
        score: Trust score (0.0-1.0).

    Returns:
        Integer trust score in [0, 1000].
    """
    return max(0, min(1000, round(score * 1000)))
