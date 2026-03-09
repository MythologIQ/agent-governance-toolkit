# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Heuristic patterns for FailSafe sentinel analysis.

Regex-based pattern matching against common vulnerability categories
(OWASP, CWE) and a risk classifier combining path and content signals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class PatternCategory(str, Enum):
    """Broad category of a heuristic vulnerability pattern."""

    INJECTION = "injection"
    AUTH = "auth"
    CRYPTO = "crypto"
    SECRETS = "secrets"
    PII = "pii"
    RESOURCE = "resource"
    LOGIC = "logic"
    COMPLEXITY = "complexity"
    EXISTENCE = "existence"
    DEPENDENCY = "dependency"


class PatternSeverity(str, Enum):
    """Severity level for a detected pattern match."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Severity ordering for sort (lower index = more severe).
_SEVERITY_ORDER = {
    PatternSeverity.CRITICAL: 0,
    PatternSeverity.HIGH: 1,
    PatternSeverity.MEDIUM: 2,
    PatternSeverity.LOW: 3,
}


@dataclass(frozen=True)
class HeuristicPattern:
    """A single regex-based heuristic code pattern."""

    id: str
    name: str
    category: PatternCategory
    severity: PatternSeverity
    cwe: str
    pattern: str
    description: str
    remediation: str
    false_positive_rate: float = 0.0


@dataclass(frozen=True)
class PatternMatch:
    """A single match of a heuristic pattern against source content."""

    pattern: HeuristicPattern
    line_number: int
    matched_text: str


def _p(
    id: str, name: str, cat: PatternCategory, sev: PatternSeverity,
    cwe: str, pattern: str, desc: str, fix: str, fpr: float = 0.0,
) -> HeuristicPattern:
    return HeuristicPattern(id, name, cat, sev, cwe, pattern, desc, fix, fpr)


_INJ = PatternCategory.INJECTION
_SEC = PatternCategory.SECRETS
_PII = PatternCategory.PII
_CMP = PatternCategory.COMPLEXITY
_AUT = PatternCategory.AUTH
_CRY = PatternCategory.CRYPTO
_DEP = PatternCategory.DEPENDENCY
_C = PatternSeverity.CRITICAL
_H = PatternSeverity.HIGH
_M = PatternSeverity.MEDIUM
_L = PatternSeverity.LOW

DEFAULT_PATTERNS: tuple[HeuristicPattern, ...] = (
    _p("INJ001", "SQL Injection Risk", _INJ, _C, "CWE-89",
       r"\b(execute|query|raw)\s*\([^)]*\+[^)]*\)",
       "SQL string concatenation detected.", "Use parameterised queries."),
    _p("INJ002", "Command Injection Risk", _INJ, _C, "CWE-78",
       r"\b(exec|spawn|system|popen)\s*\([^)]*\+[^)]*\)",
       "Command string concatenation detected.", "Use subprocess with argument lists."),
    _p("SEC001", "Hardcoded API Key", _SEC, _C, "CWE-798",
       r"""(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
       "Hardcoded API key found.", "Store secrets in env vars or a vault."),
    _p("SEC002", "Hardcoded Password", _SEC, _C, "CWE-798",
       r"""(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""",
       "Hardcoded password found.", "Store credentials in env vars or a vault."),
    _p("PII001", "Social Security Number", _PII, _H, "CWE-359",
       r"\b\d{3}-\d{2}-\d{4}\b",
       "Possible SSN pattern detected.", "Remove or mask PII before committing."),
    _p("PII002", "Credit Card Number", _PII, _H, "CWE-359",
       r"\b(?:\d{4}[- ]?){3}\d{4}\b",
       "Possible credit card number detected.", "Remove or tokenise payment card data."),
    _p("CMP001", "Deeply Nested Logic", _CMP, _M, "CWE-1121",
       r"(?:if|for|while)\s.*\{[\s\S]*(?:if|for|while)\s.*\{[\s\S]*(?:if|for|while)",
       "Three or more nesting levels detected.", "Extract inner branches into helpers."),
    _p("AUTH001", "Password in URL", _AUT, _H, "CWE-522",
       r"""(?i)https?://[^:]+:[^@]+@""",
       "Credentials embedded in URL.", "Pass credentials via headers or env vars."),
    _p("CRY001", "Weak Hash Algorithm", _CRY, _H, "CWE-328",
       r"""(?i)\b(md5|sha1)\s*\(""",
       "Use of weak hash algorithm (MD5/SHA-1).", "Use SHA-256 or stronger."),
    _p("DEP001", "Pinned Exact Version", _DEP, _L, "CWE-1104",
       r"""==\d+\.\d+\.\d+""",
       "Pinned exact dependency version.", "Consider compatible-release (~=) specifiers."),
)

_L3_PATH_TRIGGERS: tuple[str, ...] = (
    "auth", "login", "password", "payment", "billing",
    "encrypt", "crypto", "migration", "admin", "secret",
    "credential", "token",
)

_L1_PATH_TRIGGERS: tuple[str, ...] = (
    "readme", "changelog", "license", ".md", ".txt",
)

# Keywords that trigger L3 when found anywhere in content.
# Covers security-sensitive operations not caught by regex patterns.
_L3_CONTENT_TRIGGERS: tuple[str, ...] = (
    "create table", "drop table", "alter table",
    "authenticate", "bcrypt", "aes", "rsa", "private_key",
)


def match_content(
    content: str,
    patterns: Sequence[HeuristicPattern] | None = None,
) -> list[PatternMatch]:
    """Run heuristic patterns against *content* line by line.

    Args:
        content: Source text to scan.
        patterns: Pattern set to apply.  Defaults to ``DEFAULT_PATTERNS``.

    Returns:
        Matches sorted by severity (CRITICAL first, then by line number).
    """
    active = patterns if patterns is not None else DEFAULT_PATTERNS
    compiled = [(p, re.compile(p.pattern)) for p in active]
    matches: list[PatternMatch] = []

    for line_no, line in enumerate(content.splitlines(), start=1):
        for pat, regex in compiled:
            m = regex.search(line)
            if m:
                matches.append(PatternMatch(
                    pattern=pat,
                    line_number=line_no,
                    matched_text=m.group(),
                ))

    matches.sort(key=lambda pm: (
        _SEVERITY_ORDER[pm.pattern.severity],
        pm.line_number,
    ))
    return matches


def classify_risk_from_matches(
    matches: list[PatternMatch],
    file_path: str,
) -> str:
    """Derive a risk grade from pattern matches and file path.

    Args:
        matches: Results from :func:`match_content`.
        file_path: Path to the file being evaluated.

    Returns:
        ``"L3"`` if any CRITICAL match or L3 path trigger is present,
        ``"L2"`` if any HIGH match, otherwise ``"L1"``.
    """
    lower_path = file_path.lower()

    if any(t in lower_path for t in _L3_PATH_TRIGGERS):
        return "L3"

    for pm in matches:
        if pm.pattern.severity == PatternSeverity.CRITICAL:
            return "L3"

    for pm in matches:
        if pm.pattern.severity == PatternSeverity.HIGH:
            return "L2"

    return "L1"


def classify_risk(file_path: str, content: str = "") -> str:
    """Combined path + content risk classification.

    Drop-in replacement for ``LocalFailSafeClient._classify_risk``.
    Checks L1 doc paths first, then L3 path triggers, then runs
    heuristic pattern matching on *content*.

    Args:
        file_path: File path (or action string) to evaluate.
        content: Optional source content to scan for patterns.

    Returns:
        ``"L1"``, ``"L2"``, or ``"L3"``.
    """
    lower_path = file_path.lower()

    # L3 path triggers take priority.
    if any(t in lower_path for t in _L3_PATH_TRIGGERS):
        return "L3"

    # Content-based classification.
    if content:
        lower_content = content.lower()
        if any(t in lower_content for t in _L3_CONTENT_TRIGGERS):
            return "L3"
        matches = match_content(content)
        for pm in matches:
            if pm.pattern.severity == PatternSeverity.CRITICAL:
                return "L3"
        for pm in matches:
            if pm.pattern.severity == PatternSeverity.HIGH:
                return "L2"

    # L1 documentation / safe paths.
    if any(t in lower_path for t in _L1_PATH_TRIGGERS):
        return "L1"

    return "L2"
