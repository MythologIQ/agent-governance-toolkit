# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for the Shadow Genome failure-mode recording system."""

from __future__ import annotations

import pytest

from agent_failsafe.shadow_genome import (
    FailureMode,
    InMemoryShadowGenomeStore,
    RemediationStatus,
    ShadowGenomeEntry,
    classify_failure_mode,
    generate_negative_constraint,
    get_constraints_for_agent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    *,
    entry_id: str = "sg-001",
    agent_did: str = "did:myth:scrivener:aabbccdd",
    failure_mode: FailureMode = FailureMode.LOGIC_ERROR,
    file_path: str = "src/foo.py",
    description: str = "off-by-one in loop",
    negative_constraint: str = "AVOID off-by-one. REQUIRE bounds check.",
    remediation_status: RemediationStatus = RemediationStatus.UNRESOLVED,
    risk_grade: str = "L1",
    matched_patterns: tuple[str, ...] = (),
    timestamp: str = "2026-03-09T12:00:00Z",
    remediation_notes: str = "",
    resolved_by: str = "",
) -> ShadowGenomeEntry:
    return ShadowGenomeEntry(
        entry_id=entry_id,
        agent_did=agent_did,
        failure_mode=failure_mode,
        file_path=file_path,
        description=description,
        negative_constraint=negative_constraint,
        remediation_status=remediation_status,
        risk_grade=risk_grade,
        matched_patterns=matched_patterns,
        timestamp=timestamp,
        remediation_notes=remediation_notes,
        resolved_by=resolved_by,
    )


# ---------------------------------------------------------------------------
# TestFailureMode
# ---------------------------------------------------------------------------


class TestFailureMode:
    """Verify FailureMode enum membership and string values."""

    def test_has_all_ten_members(self) -> None:
        assert len(FailureMode) == 10

    def test_string_values_are_lowercase(self) -> None:
        for member in FailureMode:
            assert member.value == member.value.lower()
            assert member.value == member.name.lower()


# ---------------------------------------------------------------------------
# TestRemediationStatus
# ---------------------------------------------------------------------------


class TestRemediationStatus:
    """Verify RemediationStatus enum membership and lifecycle values."""

    def test_has_all_five_members(self) -> None:
        assert len(RemediationStatus) == 5

    def test_lifecycle_values_present(self) -> None:
        expected = {"unresolved", "in_progress", "resolved", "wont_fix", "superseded"}
        actual = {s.value for s in RemediationStatus}
        assert actual == expected


# ---------------------------------------------------------------------------
# TestShadowGenomeEntry
# ---------------------------------------------------------------------------


class TestShadowGenomeEntry:
    """Verify frozen dataclass behaviour and defaults."""

    def test_frozen_immutability(self) -> None:
        entry = _make_entry()
        with pytest.raises(AttributeError):
            entry.description = "modified"  # type: ignore[misc]

    def test_default_values(self) -> None:
        entry = ShadowGenomeEntry(
            entry_id="sg-min",
            agent_did="did:myth:scrivener:00",
            failure_mode=FailureMode.OTHER,
            file_path="x.py",
            description="minimal",
            negative_constraint="none",
        )
        assert entry.remediation_status is RemediationStatus.UNRESOLVED
        assert entry.risk_grade == "L1"
        assert entry.matched_patterns == ()
        assert entry.timestamp == ""
        assert entry.remediation_notes == ""
        assert entry.resolved_by == ""

    def test_full_construction(self) -> None:
        entry = _make_entry(
            entry_id="sg-full",
            matched_patterns=("injection", "command"),
            remediation_notes="patched",
            resolved_by="did:myth:sentinel:ff",
        )
        assert entry.entry_id == "sg-full"
        assert entry.matched_patterns == ("injection", "command")
        assert entry.remediation_notes == "patched"
        assert entry.resolved_by == "did:myth:sentinel:ff"


# ---------------------------------------------------------------------------
# TestClassifyFailureMode
# ---------------------------------------------------------------------------


class TestClassifyFailureMode:
    """Verify pattern-to-failure-mode classification logic."""

    def test_injection_patterns(self) -> None:
        result = classify_failure_mode(["injection"], "L2", "user input")
        assert result is FailureMode.INJECTION_VULNERABILITY

    def test_command_pattern(self) -> None:
        result = classify_failure_mode(["command"], "L2", "shell exec")
        assert result is FailureMode.INJECTION_VULNERABILITY

    def test_secret_patterns(self) -> None:
        result = classify_failure_mode(["api_key"], "L3", "exposed key")
        assert result is FailureMode.SECRET_EXPOSURE

    def test_pii_patterns(self) -> None:
        result = classify_failure_mode([], "L2", "found ssn in logs")
        assert result is FailureMode.PII_LEAK

    def test_complexity_patterns(self) -> None:
        result = classify_failure_mode(["nesting"], "L1", "too deep")
        assert result is FailureMode.HIGH_COMPLEXITY

    def test_unknown_falls_back_to_other(self) -> None:
        result = classify_failure_mode([], "L1", "something weird happened")
        assert result is FailureMode.OTHER


# ---------------------------------------------------------------------------
# TestGenerateNegativeConstraint
# ---------------------------------------------------------------------------


class TestGenerateNegativeConstraint:
    """Verify constraint template rendering per failure mode."""

    def test_injection_constraint(self) -> None:
        c = generate_negative_constraint(
            FailureMode.INJECTION_VULNERABILITY, "api.py", "sql concat"
        )
        assert "AVOID" in c
        assert "REQUIRE" in c
        assert "api.py" in c

    def test_secret_constraint(self) -> None:
        c = generate_negative_constraint(
            FailureMode.SECRET_EXPOSURE, "config.py", "hardcoded token"
        )
        assert "secret" in c.lower() or "credential" in c.lower()
        assert "config.py" in c

    def test_complexity_constraint(self) -> None:
        c = generate_negative_constraint(
            FailureMode.HIGH_COMPLEXITY, "engine.py", "deep nesting"
        )
        assert "complexity" in c.lower()
        assert "engine.py" in c

    def test_pii_constraint(self) -> None:
        c = generate_negative_constraint(
            FailureMode.PII_LEAK, "log.py", "ssn in output"
        )
        assert "PII" in c
        assert "log.py" in c


# ---------------------------------------------------------------------------
# TestInMemoryShadowGenomeStore
# ---------------------------------------------------------------------------


class TestInMemoryShadowGenomeStore:
    """Verify in-memory store recording and query filtering."""

    def test_record_and_query_all(self) -> None:
        store = InMemoryShadowGenomeStore()
        e1 = _make_entry(entry_id="sg-1")
        e2 = _make_entry(entry_id="sg-2")
        store.record(e1)
        store.record(e2)
        results = store.query()
        assert len(results) == 2

    def test_filter_by_agent_did(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_make_entry(agent_did="did:mesh:aaa"))
        store.record(_make_entry(agent_did="did:mesh:bbb"))
        results = store.query(agent_did="did:mesh:aaa")
        assert len(results) == 1
        assert results[0].agent_did == "did:mesh:aaa"

    def test_filter_by_failure_mode(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(_make_entry(failure_mode=FailureMode.PII_LEAK))
        store.record(_make_entry(failure_mode=FailureMode.LOGIC_ERROR))
        results = store.query(failure_mode=FailureMode.PII_LEAK)
        assert len(results) == 1
        assert results[0].failure_mode is FailureMode.PII_LEAK

    def test_filter_by_status(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(
            _make_entry(remediation_status=RemediationStatus.RESOLVED)
        )
        store.record(
            _make_entry(remediation_status=RemediationStatus.UNRESOLVED)
        )
        results = store.query(status=RemediationStatus.RESOLVED)
        assert len(results) == 1
        assert results[0].remediation_status is RemediationStatus.RESOLVED

    def test_limit_respected(self) -> None:
        store = InMemoryShadowGenomeStore()
        for i in range(10):
            store.record(_make_entry(entry_id=f"sg-{i}"))
        results = store.query(limit=3)
        assert len(results) == 3


# ---------------------------------------------------------------------------
# TestGetConstraintsForAgent
# ---------------------------------------------------------------------------


class TestGetConstraintsForAgent:
    """Verify agent constraint retrieval for learning injection."""

    def test_returns_constraint_strings(self) -> None:
        store = InMemoryShadowGenomeStore()
        store.record(
            _make_entry(
                agent_did="did:mesh:agent1",
                negative_constraint="AVOID X. REQUIRE Y.",
            )
        )
        constraints = get_constraints_for_agent(store, "did:mesh:agent1")
        assert len(constraints) == 1
        assert constraints[0] == "AVOID X. REQUIRE Y."

    def test_respects_limit(self) -> None:
        store = InMemoryShadowGenomeStore()
        for i in range(5):
            store.record(
                _make_entry(
                    entry_id=f"sg-{i}",
                    agent_did="did:mesh:agent2",
                    negative_constraint=f"constraint-{i}",
                )
            )
        constraints = get_constraints_for_agent(
            store, "did:mesh:agent2", limit=2
        )
        assert len(constraints) == 2

    def test_empty_store_returns_empty(self) -> None:
        store = InMemoryShadowGenomeStore()
        constraints = get_constraints_for_agent(store, "did:mesh:nobody")
        assert constraints == []


# ---------------------------------------------------------------------------
# TestInMemoryShadowGenomeStore — FIFO Eviction
# ---------------------------------------------------------------------------


class TestStoreEviction:
    """Verify max_entries cap with FIFO eviction."""

    def test_evicts_oldest_when_full(self) -> None:
        store = InMemoryShadowGenomeStore(max_entries=3)
        for i in range(5):
            store.record(_make_entry(entry_id=f"sg-{i}"))
        results = store.query()
        assert len(results) == 3
        ids = [r.entry_id for r in results]
        assert "sg-0" not in ids
        assert "sg-1" not in ids

    def test_max_entries_minimum_is_one(self) -> None:
        store = InMemoryShadowGenomeStore(max_entries=0)
        store.record(_make_entry(entry_id="sg-only"))
        assert len(store.query()) == 1

    def test_default_max_entries(self) -> None:
        store = InMemoryShadowGenomeStore()
        assert store._max_entries == 10_000
