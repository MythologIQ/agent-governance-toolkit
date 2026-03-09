# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""FailSafe governance bridge for Agent Governance Toolkit.

Bridges FailSafe's deterministic governance controls into the toolkit's
policy enforcement, trust mesh, reliability, and execution isolation layers.
"""

from agent_failsafe.bridge import FailSafeBridge, FailSafeEvent
from agent_failsafe.client import LocalFailSafeClient
from agent_failsafe.interceptor import (
    FailSafeClient,
    FailSafeIntegration,
    FailSafeInterceptor,
)
from agent_failsafe.patterns import (
    HeuristicPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    classify_risk,
    match_content,
)
from agent_failsafe.ring_adapter import FailSafeRingAdapter
from agent_failsafe.shadow_genome import (
    FailureMode,
    InMemoryShadowGenomeStore,
    RemediationStatus,
    ShadowGenomeEntry,
    ShadowGenomeStore,
    classify_failure_mode,
    generate_negative_constraint,
    get_constraints_for_agent,
)
from agent_failsafe.sli import EscalationRateSLI, FailSafeComplianceSLI
from agent_failsafe.trust import (
    DEFAULT_TRUST_CONFIG,
    TrustConfig,
    TrustStage,
    apply_outcome,
    calculate_influence_weight,
    determine_stage,
    is_probationary,
    score_to_mesh_trust,
)
from agent_failsafe.trust_mapper import FailSafeTrustMapper
from agent_failsafe.types import GovernanceDecision, GovernanceEventLog

__all__ = [
    # Core Types
    "GovernanceDecision",
    "GovernanceEventLog",
    # Agent OS Adapter
    "FailSafeClient",
    "FailSafeInterceptor",
    "FailSafeIntegration",
    "LocalFailSafeClient",
    # Shadow Genome
    "FailureMode",
    "RemediationStatus",
    "ShadowGenomeEntry",
    "ShadowGenomeStore",
    "InMemoryShadowGenomeStore",
    "classify_failure_mode",
    "generate_negative_constraint",
    "get_constraints_for_agent",
    # Heuristic Patterns
    "HeuristicPattern",
    "PatternCategory",
    "PatternSeverity",
    "PatternMatch",
    "match_content",
    "classify_risk",
    # SRE Bridge
    "FailSafeBridge",
    "FailSafeEvent",
    "FailSafeComplianceSLI",
    "EscalationRateSLI",
    # Trust Dynamics
    "TrustStage",
    "TrustConfig",
    "DEFAULT_TRUST_CONFIG",
    "determine_stage",
    "apply_outcome",
    "is_probationary",
    "calculate_influence_weight",
    "score_to_mesh_trust",
    # Trust Mesh
    "FailSafeTrustMapper",
    # Hypervisor
    "FailSafeRingAdapter",
]
