# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""FailSafe Governance Bridge — Agent OS Adapter.

Plugs FailSafe's risk-graded governance into the Agent OS interceptor
and integration framework.  Design principle: FailSafe adapts to the
toolkit, not the reverse.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    ToolCallRequest,
    ToolCallResult,
)

from agent_failsafe.types import GovernanceDecision

logger = logging.getLogger(__name__)


# ── Client Protocol ─────────────────────────────────────────


class FailSafeClient(Protocol):
    """Toolkit-side interface to FailSafe governance."""

    def evaluate(
        self,
        action: str,
        agent_did: str,
        context: dict[str, Any],
        artifact_path: str | None = None,
    ) -> GovernanceDecision: ...

    def query_ledger(
        self,
        agent_did: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]: ...


# ── Interceptor ──────────────────────────────────────────────


class FailSafeInterceptor:
    """ToolCallInterceptor that delegates to a FailSafeClient."""

    def __init__(self, client: FailSafeClient, agent_did: str = "") -> None:
        self._client = client
        self._agent_did = agent_did

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        """Evaluate the tool call via FailSafe and translate the decision."""
        decision = self._client.evaluate(
            action=request.tool_name,
            agent_did=self._agent_did,
            context=request.metadata,
            artifact_path=request.metadata.get("artifact_path"),
        )
        audit = {
            "risk_grade": decision.risk_grade,
            "nonce": decision.nonce,
            "trace_id": decision.trace_id,
        }
        if not decision.allowed:
            return ToolCallResult(
                allowed=False, reason=decision.reason, audit_entry=audit,
            )
        return ToolCallResult(allowed=True, audit_entry=audit)


# ── Integration ──────────────────────────────────────────────


class FailSafeIntegration(BaseIntegration):
    """BaseIntegration wiring FailSafe governance into Agent OS lifecycle."""

    def __init__(
        self,
        client: FailSafeClient,
        policy: GovernancePolicy | None = None,
    ) -> None:
        super().__init__(policy=policy)
        self._client = client

    def wrap(self, agent: Any) -> Any:
        """Pass-through: governance is enforced via the interceptor layer."""
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        """Pass-through: no wrapper to remove."""
        return governed_agent

    def pre_execute(
        self, ctx: ExecutionContext, input_data: Any,
    ) -> tuple[bool, str | None]:
        """Run base policy checks, then FailSafe evaluation."""
        allowed, reason = super().pre_execute(ctx, input_data)
        if not allowed:
            return allowed, reason
        decision = self._client.evaluate(
            action=str(input_data),
            agent_did=ctx.agent_id,
            context={"session_id": ctx.session_id},
        )
        if not decision.allowed:
            self.emit(GovernanceEventType.POLICY_VIOLATION, {
                "agent_id": ctx.agent_id,
                "risk_grade": decision.risk_grade,
                "nonce": decision.nonce,
            })
        return decision.allowed, decision.reason

    def post_execute(
        self, ctx: ExecutionContext, output_data: Any,
    ) -> tuple[bool, str | None]:
        """Delegate to base post_execute (FailSafe records during pre)."""
        return super().post_execute(ctx, output_data)
