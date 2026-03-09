# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""FailSafe LocalFailSafeClient — in-process governance client.

Reads FailSafe's YAML risk policies and writes to the shared SQLite
ledger.  No Node.js runtime dependency.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
import time
from typing import Any

from agent_failsafe.patterns import classify_risk
from agent_failsafe.types import GovernanceDecision

logger = logging.getLogger(__name__)

_LEDGER_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS ledger_entries ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "timestamp TEXT, event_type TEXT, agent_did TEXT, "
    "risk_grade TEXT, artifact_path TEXT, nonce TEXT, "
    "allowed INTEGER, reason TEXT, entry_hash TEXT, prev_hash TEXT)"
)

_MAX_QUERY_LIMIT = 1000


# ── Client Implementation ────────────────────────────────────


class LocalFailSafeClient:
    """In-process FailSafe client backed by YAML config and SQLite ledger."""

    def __init__(
        self,
        config_dir: str = ".failsafe/config",
        ledger_path: str = ".failsafe/ledger/soa_ledger.db",
    ) -> None:
        self._config_dir = config_dir
        self._ledger_path = ledger_path
        self._path_triggers, self._content_triggers = self._load_triggers()
        self._ensure_ledger()

    def _load_triggers(self) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Load risk triggers from YAML config, falling back to defaults."""
        try:
            import yaml
        except ImportError:
            return {}, {}
        policy_path = os.path.join(
            self._config_dir, "policies", "risk_grading.yaml",
        )
        if not os.path.isfile(policy_path):
            return {}, {}
        with open(policy_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        ac = data.get("auto_classification", {})
        return ac.get("file_path_triggers", {}), ac.get("content_triggers", {})

    def _ensure_ledger(self) -> None:
        """Create ledger database and table if missing."""
        os.makedirs(os.path.dirname(self._ledger_path) or ".", exist_ok=True)
        with sqlite3.connect(self._ledger_path) as conn:
            conn.execute(_LEDGER_SCHEMA)

    def evaluate(
        self,
        action: str,
        agent_did: str,
        context: dict[str, Any],
        artifact_path: str | None = None,
    ) -> GovernanceDecision:
        """Classify risk, apply policy, record to ledger, return decision."""
        path_hint = f"{action} {artifact_path or ''}"
        grade = classify_risk(path_hint, str(context))
        nonce = secrets.token_hex(32)
        decision = self._apply_policy(grade, action, nonce)
        entry_id = self._append_ledger(
            agent_did, grade, artifact_path, nonce, decision,
        )
        return GovernanceDecision(
            allowed=decision.allowed,
            risk_grade=grade,
            reason=decision.reason,
            nonce=nonce,
            conditions=tuple(decision.conditions),
            ledger_entry_id=str(entry_id),
            trace_id=context.get("trace_id", ""),
        )

    @staticmethod
    def _apply_policy(grade: str, action: str, nonce: str) -> GovernanceDecision:
        if grade == "L1":
            return GovernanceDecision(
                allowed=True, risk_grade=grade,
                reason="Auto-approved (L1)", nonce=nonce,
            )
        if grade == "L3":
            return GovernanceDecision(
                allowed=False, risk_grade=grade,
                reason=f"Denied: {action} requires human approval (L3)",
                nonce=nonce,
            )
        return GovernanceDecision(
            allowed=True, risk_grade=grade,
            reason="Allowed with conditions (L2)", nonce=nonce,
            conditions=("requires_human_review",),
        )

    def _append_ledger(
        self,
        agent_did: str,
        grade: str,
        artifact_path: str | None,
        nonce: str,
        decision: GovernanceDecision,
    ) -> int:
        """Insert a ledger row atomically and return its id."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        art = artifact_path or ""
        allowed_int = int(decision.allowed)
        with sqlite3.connect(self._ledger_path) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            row = conn.execute(
                "SELECT entry_hash FROM ledger_entries "
                "ORDER BY id DESC LIMIT 1",
            ).fetchone()
            prev_hash = row[0] if row else "genesis"
            entry_hash = hashlib.sha256(
                f"{prev_hash}:{agent_did}:{grade}:{art}:"
                f"{nonce}:{allowed_int}:{decision.reason}:{ts}".encode(),
            ).hexdigest()
            cur = conn.execute(
                "INSERT INTO ledger_entries "
                "(timestamp, event_type, agent_did, risk_grade, "
                "artifact_path, nonce, allowed, reason, "
                "entry_hash, prev_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ts, "governance_eval", agent_did, grade,
                 art, nonce, allowed_int, decision.reason,
                 entry_hash, prev_hash),
            )
            return cur.lastrowid or 0

    def query_ledger(
        self, agent_did: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return recent ledger entries for a given agent DID."""
        safe_limit = max(1, min(limit, _MAX_QUERY_LIMIT))
        with sqlite3.connect(self._ledger_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM ledger_entries WHERE agent_did=? "
                "ORDER BY id DESC LIMIT ?",
                (agent_did, safe_limit),
            ).fetchall()
        return [dict(r) for r in rows]
