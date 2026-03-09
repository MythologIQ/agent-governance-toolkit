# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Core types for the FailSafe governance bridge.

Defines the canonical ``GovernanceDecision`` value object and
``GovernanceEventLog`` Protocol — the single source of truth
consumed by all bridge modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, Sequence


@dataclass(frozen=True)
class GovernanceDecision:
    """Immutable result of a FailSafe governance evaluation."""

    allowed: bool
    risk_grade: str
    reason: str
    nonce: str
    conditions: tuple[str, ...] = ()
    ledger_entry_id: str = ""
    trace_id: str = ""


class GovernanceEventLog(Protocol):
    """Query interface for persisted governance events.

    Structurally satisfied by ``agentmesh.governance.audit.AuditLog``
    without requiring a cross-package import.
    """

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
    ) -> Any: ...

    def query(
        self,
        agent_did: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        outcome: str | None = None,
        limit: int = 100,
    ) -> Sequence[Any]: ...
