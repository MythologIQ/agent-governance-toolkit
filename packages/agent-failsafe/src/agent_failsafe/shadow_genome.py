# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Shadow Genome: failure-mode recording and negative-constraint generation.

Captures *how agents fail* and generates machine-readable negative constraints
("AVOID X / REQUIRE Y") that can be injected into agent prompts to prevent
recurrence.  This is the learning loop that turns past mistakes into
deterministic guardrails.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Sequence


class FailureMode(str, Enum):
    """Canonical taxonomy of agent failure modes."""

    HALLUCINATION = "hallucination"
    INJECTION_VULNERABILITY = "injection_vulnerability"
    LOGIC_ERROR = "logic_error"
    SPEC_VIOLATION = "spec_violation"
    HIGH_COMPLEXITY = "high_complexity"
    SECRET_EXPOSURE = "secret_exposure"
    PII_LEAK = "pii_leak"
    DEPENDENCY_CONFLICT = "dependency_conflict"
    TRUST_VIOLATION = "trust_violation"
    OTHER = "other"


class RemediationStatus(str, Enum):
    """Lifecycle status of a recorded failure entry."""

    UNRESOLVED = "unresolved"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WONT_FIX = "wont_fix"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class ShadowGenomeEntry:
    """Immutable record of a single agent failure event.

    Attributes:
        entry_id: Unique identifier for this genome entry.
        agent_did: DID of the agent that produced the failure.
        failure_mode: Classified failure category.
        file_path: Source file where the failure was observed.
        description: Human-readable description of the failure.
        negative_constraint: Machine-readable AVOID/REQUIRE directive.
        remediation_status: Current lifecycle status.
        risk_grade: FailSafe risk grade (L1, L2, L3).
        matched_patterns: Pattern strings that triggered classification.
        timestamp: ISO 8601 timestamp of the failure event.
        remediation_notes: Free-text notes on remediation progress.
        resolved_by: Identifier of the agent or human who resolved it.
    """

    entry_id: str
    agent_did: str
    failure_mode: FailureMode
    file_path: str
    description: str
    negative_constraint: str
    remediation_status: RemediationStatus = RemediationStatus.UNRESOLVED
    risk_grade: str = "L1"
    matched_patterns: tuple[str, ...] = ()
    timestamp: str = ""
    remediation_notes: str = ""
    resolved_by: str = ""


class ShadowGenomeStore(Protocol):
    """Abstract storage interface for shadow genome entries."""

    def record(self, entry: ShadowGenomeEntry) -> None:
        """Persist a new shadow genome entry."""
        ...

    def query(
        self,
        agent_did: str | None = None,
        failure_mode: FailureMode | None = None,
        status: RemediationStatus | None = None,
        limit: int = 50,
    ) -> Sequence[ShadowGenomeEntry]:
        """Retrieve entries matching the given filters."""
        ...


class InMemoryShadowGenomeStore:
    """List-backed shadow genome store for testing and lightweight use."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: list[ShadowGenomeEntry] = []
        self._max_entries = max(1, max_entries)

    def record(self, entry: ShadowGenomeEntry) -> None:
        """Append *entry* to the in-memory list, evicting oldest if full."""
        if len(self._entries) >= self._max_entries:
            self._entries = self._entries[-(self._max_entries - 1):]
        self._entries.append(entry)

    def query(
        self,
        agent_did: str | None = None,
        failure_mode: FailureMode | None = None,
        status: RemediationStatus | None = None,
        limit: int = 50,
    ) -> Sequence[ShadowGenomeEntry]:
        """Return entries matching all non-None filters, newest first."""
        results: list[ShadowGenomeEntry] = []
        for entry in reversed(self._entries):
            if agent_did is not None and entry.agent_did != agent_did:
                continue
            if failure_mode is not None and entry.failure_mode != failure_mode:
                continue
            if status is not None and entry.remediation_status != status:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results


# -- Classification helpers --------------------------------------------------

_PATTERN_MAP: list[tuple[list[str], FailureMode]] = [
    (["injection", "command"], FailureMode.INJECTION_VULNERABILITY),
    (["secret", "credential", "api_key"], FailureMode.SECRET_EXPOSURE),
    (["pii", "ssn", "credit_card"], FailureMode.PII_LEAK),
    (["complexity", "nesting"], FailureMode.HIGH_COMPLEXITY),
    (["trust", "violation"], FailureMode.TRUST_VIOLATION),
    (["dependency"], FailureMode.DEPENDENCY_CONFLICT),
    (["spec", "drift"], FailureMode.SPEC_VIOLATION),
    (["hallucination"], FailureMode.HALLUCINATION),
    (["logic"], FailureMode.LOGIC_ERROR),
]


def classify_failure_mode(
    matched_patterns: Sequence[str],
    risk_grade: str,
    reason: str,
) -> FailureMode:
    """Derive a ``FailureMode`` from pattern keywords and context.

    Args:
        matched_patterns: Pattern strings that triggered the evaluation.
        risk_grade: FailSafe risk grade (L1/L2/L3).
        reason: Human-readable reason from the governance decision.

    Returns:
        The most specific ``FailureMode`` that matches, or ``OTHER``.
    """
    searchable = " ".join(matched_patterns).lower() + " " + reason.lower()
    for keywords, mode in _PATTERN_MAP:
        if any(kw in searchable for kw in keywords):
            return mode
    return FailureMode.OTHER


# -- Negative constraint generation ------------------------------------------

_CONSTRAINT_TEMPLATES: dict[FailureMode, str] = {
    FailureMode.HALLUCINATION:
        "AVOID generating unverified claims in {file_path}. "
        "REQUIRE citations or explicit uncertainty markers.",
    FailureMode.INJECTION_VULNERABILITY:
        "AVOID passing unsanitised input to shell or SQL in {file_path}. "
        "REQUIRE parameterised queries and input validation.",
    FailureMode.LOGIC_ERROR:
        "AVOID repeating logic error in {file_path}: {description}. "
        "REQUIRE explicit pre/post-condition checks.",
    FailureMode.SPEC_VIOLATION:
        "AVOID deviating from specification in {file_path}. "
        "REQUIRE conformance to documented API contracts.",
    FailureMode.HIGH_COMPLEXITY:
        "AVOID exceeding complexity thresholds in {file_path}. "
        "REQUIRE functions under 40 lines and nesting depth under 3.",
    FailureMode.SECRET_EXPOSURE:
        "AVOID embedding secrets or credentials in {file_path}. "
        "REQUIRE environment variables or secret managers.",
    FailureMode.PII_LEAK:
        "AVOID logging or transmitting PII in {file_path}. "
        "REQUIRE redaction before persistence or network transfer.",
    FailureMode.DEPENDENCY_CONFLICT:
        "AVOID adding conflicting dependencies affecting {file_path}. "
        "REQUIRE compatibility verification before introduction.",
    FailureMode.TRUST_VIOLATION:
        "AVOID bypassing trust verification in {file_path}. "
        "REQUIRE valid DID and trust score checks before access.",
    FailureMode.OTHER:
        "AVOID repeating failure in {file_path}: {description}. "
        "REQUIRE additional review before similar changes.",
}


def generate_negative_constraint(
    failure_mode: FailureMode,
    file_path: str,
    description: str,
) -> str:
    """Produce a human- and machine-readable AVOID/REQUIRE directive.

    Args:
        failure_mode: The classified failure category.
        file_path: Path to the file where the failure occurred.
        description: Short description of the failure.

    Returns:
        A constraint string formatted with *file_path* and *description*.
    """
    template = _CONSTRAINT_TEMPLATES.get(
        failure_mode, _CONSTRAINT_TEMPLATES[FailureMode.OTHER],
    )
    return template.format(file_path=file_path, description=description)


# -- Agent learning injection ------------------------------------------------


def get_constraints_for_agent(
    store: ShadowGenomeStore,
    agent_did: str,
    limit: int = 10,
) -> list[str]:
    """Retrieve recent negative constraints for prompt injection.

    Args:
        store: A ``ShadowGenomeStore`` implementation.
        agent_did: The DID of the agent to retrieve constraints for.
        limit: Maximum number of constraints to return.

    Returns:
        A list of constraint strings, most recent first.
    """
    entries = store.query(agent_did=agent_did, limit=limit)
    return [e.negative_constraint for e in entries if e.negative_constraint]
