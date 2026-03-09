# Copyright (c) MythologIQ.
# Licensed under the MIT License.
"""Tests for trust dynamics module."""

from __future__ import annotations

import dataclasses

import pytest

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


class TestTrustStage:
    """TrustStage enum tests."""

    def test_values_and_string_representation(self) -> None:
        assert TrustStage.CBT == "CBT"
        assert TrustStage.KBT == "KBT"
        assert TrustStage.IBT == "IBT"
        assert str(TrustStage.CBT) == "TrustStage.CBT"


class TestTrustConfig:
    """TrustConfig dataclass tests."""

    def test_frozen_and_default_values(self) -> None:
        config = TrustConfig()
        assert config.default_trust == 0.35
        assert config.success_delta == 0.05
        assert config.failure_delta == -0.10
        assert config.violation_penalty == -0.25
        assert config.probation_floor == 0.35
        assert config.probation_verifications == 5
        assert config.probation_days == 30
        assert config.cbt_max == 0.5
        assert config.kbt_max == 0.8
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.default_trust = 0.5  # type: ignore[misc]


class TestDetermineStage:
    """determine_stage function tests."""

    def test_cbt_at_low_score(self) -> None:
        assert determine_stage(0.3) == TrustStage.CBT

    def test_kbt_at_mid_score(self) -> None:
        assert determine_stage(0.6) == TrustStage.KBT

    def test_ibt_at_high_score(self) -> None:
        assert determine_stage(0.9) == TrustStage.IBT

    def test_boundary_at_cbt_max_is_kbt(self) -> None:
        assert determine_stage(0.5) == TrustStage.KBT

    def test_boundary_at_kbt_max_is_ibt(self) -> None:
        assert determine_stage(0.8) == TrustStage.IBT


class TestApplyOutcome:
    """apply_outcome function tests."""

    def test_success_adds_delta(self) -> None:
        result = apply_outcome(0.5, allowed=True, risk_grade="L1")
        assert result == pytest.approx(0.55)

    def test_failure_subtracts_delta(self) -> None:
        result = apply_outcome(0.5, allowed=False, risk_grade="L2")
        assert result == pytest.approx(0.40)

    def test_l3_violation_subtracts_penalty(self) -> None:
        result = apply_outcome(0.5, allowed=False, risk_grade="L3")
        assert result == pytest.approx(0.25)

    def test_clamped_to_floor(self) -> None:
        result = apply_outcome(0.05, allowed=False, risk_grade="L3")
        assert result == 0.0

    def test_clamped_to_ceiling(self) -> None:
        result = apply_outcome(0.98, allowed=True, risk_grade="L1")
        assert result == 1.0


class TestIsProbationary:
    """is_probationary function tests."""

    def test_new_agent_is_probationary(self) -> None:
        assert is_probationary(days_active=0, verifications_completed=0) is True

    def test_mature_agent_not_probationary(self) -> None:
        assert is_probationary(days_active=31, verifications_completed=6) is False

    def test_enough_days_but_few_verifications(self) -> None:
        assert is_probationary(days_active=30, verifications_completed=4) is True


class TestCalculateInfluenceWeight:
    """calculate_influence_weight function tests."""

    def test_probationary_returns_fixed_low(self) -> None:
        assert calculate_influence_weight(0.9, is_probationary_flag=True) == pytest.approx(0.1)

    def test_zero_score_non_probationary(self) -> None:
        assert calculate_influence_weight(0.0, is_probationary_flag=False) == pytest.approx(0.5)

    def test_max_score_non_probationary(self) -> None:
        assert calculate_influence_weight(1.0, is_probationary_flag=False) == pytest.approx(2.0)


class TestScoreToMeshTrust:
    """score_to_mesh_trust function tests."""

    def test_high_score(self) -> None:
        assert score_to_mesh_trust(0.9) == 900

    def test_low_score(self) -> None:
        assert score_to_mesh_trust(0.3) == 300

    def test_zero(self) -> None:
        assert score_to_mesh_trust(0.0) == 0

    def test_one(self) -> None:
        assert score_to_mesh_trust(1.0) == 1000

    def test_negative_clamped(self) -> None:
        assert score_to_mesh_trust(-0.5) == 0
