# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for agent_failsafe.patterns — heuristic sentinel analysis."""

from __future__ import annotations

import re

import pytest

from agent_failsafe.patterns import (
    DEFAULT_PATTERNS,
    HeuristicPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    classify_risk,
    classify_risk_from_matches,
    match_content,
)


# ── TestPatternCategory ─────────────────────────────────────


class TestPatternCategory:
    """PatternCategory enum validation."""

    def test_has_ten_values(self) -> None:
        assert len(PatternCategory) == 10


# ── TestHeuristicPattern ─────────────────────────────────────


class TestHeuristicPattern:
    """HeuristicPattern dataclass behaviour."""

    def test_frozen(self) -> None:
        pat = DEFAULT_PATTERNS[0]
        with pytest.raises(AttributeError):
            pat.name = "changed"  # type: ignore[misc]

    def test_all_fields_present(self) -> None:
        pat = DEFAULT_PATTERNS[0]
        for field_name in (
            "id", "name", "category", "severity",
            "cwe", "pattern", "description", "remediation",
            "false_positive_rate",
        ):
            assert hasattr(pat, field_name)


# ── TestDefaultPatterns ──────────────────────────────────────


class TestDefaultPatterns:
    """Validation of the built-in DEFAULT_PATTERNS tuple."""

    def test_all_patterns_compile(self) -> None:
        for pat in DEFAULT_PATTERNS:
            compiled = re.compile(pat.pattern)
            assert compiled is not None, f"{pat.id} failed to compile"

    def test_all_have_cwe(self) -> None:
        for pat in DEFAULT_PATTERNS:
            assert pat.cwe.startswith("CWE-"), f"{pat.id} missing CWE ref"


# ── TestMatchContent ─────────────────────────────────────────


class TestMatchContent:
    """Content scanning via match_content."""

    def test_sql_injection_match(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + user_id)'
        matches = match_content(code)
        ids = [m.pattern.id for m in matches]
        assert "INJ001" in ids

    def test_command_injection_match(self) -> None:
        code = 'os.popen("ls " + user_input)'
        matches = match_content(code)
        ids = [m.pattern.id for m in matches]
        assert "INJ002" in ids

    def test_hardcoded_secret_match(self) -> None:
        code = 'api_key = "sk_live_1234567890abcdef"'
        matches = match_content(code)
        ids = [m.pattern.id for m in matches]
        assert "SEC001" in ids

    def test_pii_ssn_match(self) -> None:
        code = "ssn = 123-45-6789"
        matches = match_content(code)
        ids = [m.pattern.id for m in matches]
        assert "PII001" in ids

    def test_no_match_on_clean_code(self) -> None:
        code = "x = 1 + 2\nprint(x)\n"
        matches = match_content(code)
        assert matches == []

    def test_multiple_matches_sorted_by_severity(self) -> None:
        code = (
            'api_key = "sk_live_1234567890abcdef"\n'
            "ssn = 123-45-6789\n"
        )
        matches = match_content(code)
        assert len(matches) >= 2
        severities = [m.pattern.severity for m in matches]
        assert severities[0] == PatternSeverity.CRITICAL
        assert severities[-1] == PatternSeverity.HIGH


# ── TestClassifyRisk ─────────────────────────────────────────


class TestClassifyRisk:
    """Risk classification from matches and file paths."""

    def test_l3_from_critical_match(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)'
        matches = match_content(code)
        grade = classify_risk_from_matches(matches, "src/utils.py")
        assert grade == "L3"

    def test_l2_from_high_match(self) -> None:
        code = "ssn = 123-45-6789"
        matches = match_content(code)
        grade = classify_risk_from_matches(matches, "src/utils.py")
        assert grade == "L2"

    def test_l1_from_clean(self) -> None:
        matches: list[PatternMatch] = []
        grade = classify_risk_from_matches(matches, "src/utils.py")
        assert grade == "L1"

    def test_l3_from_path_trigger(self) -> None:
        assert classify_risk("src/auth/login.py") == "L3"
        assert classify_risk("services/crypto_utils.py") == "L3"
        assert classify_risk("api/payment_handler.py") == "L3"

    def test_combined_path_and_content(self) -> None:
        # Path triggers L3 even without content.
        assert classify_risk("auth.py", "x = 1") == "L3"
        # Content with critical finding on generic path -> L3.
        code = 'password = "hunter2longpassword"'
        assert classify_risk("src/config.py", code) == "L3"
        # Clean content on a doc path -> L1.
        assert classify_risk("README.md", "just docs") == "L1"
        # Clean content on generic path -> L2.
        assert classify_risk("src/app.py", "x = 1") == "L2"

    def test_l3_from_content_triggers(self) -> None:
        """Content keywords (bcrypt, aes, etc.) trigger L3."""
        assert classify_risk("src/utils.py", "hash = bcrypt(pwd)") == "L3"
        assert classify_risk("src/utils.py", "cipher = aes(key)") == "L3"
        assert classify_risk("src/db.py", "DROP TABLE users") == "L3"
        assert classify_risk("src/db.py", "CREATE TABLE foo") == "L3"
        assert classify_risk("src/db.py", "ALTER TABLE bar") == "L3"
        assert classify_risk("src/auth.py", "authenticate(user)") == "L3"
        assert classify_risk("src/crypto.py", "rsa(key)") == "L3"
        assert classify_risk("src/cfg.py", "private_key = x") == "L3"
