"""
Tests for pipeline/scorer.py

The scorer is pure deterministic logic with no I/O.
No mocking required — every case can be exercised with direct function calls.
"""

from typing import Any
import pytest

from pipeline.scorer import (
    ScoringResult,
    compute_risk_score,
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    KEV_WEIGHT,
    EPSS_SCALE,
    REACHABILITY_MULTIPLIER,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def score(**kwargs) -> ScoringResult:
    """
    Call compute_risk_score with sensible defaults so individual tests
    only need to specify the parameter(s) they are testing.
    """
    defaults: dict[str, Any] = dict(
        cvss=5.0,
        epss=0.5,
        is_kev=False,
        kev_status='confirmed_not_kev',
        reachability_status='UNKNOWN',
        evidence_source='none',
    )
    defaults.update(kwargs)
    return compute_risk_score(**defaults)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# Arithmetic correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestArithmetic:

    def test_base_score_formula(self):
        """base = (cvss * 0.2) + (epss * 10 * 0.5) + (kev * 0.3)"""
        result = score(cvss=10.0, epss=1.0, is_kev=True, kev_status='confirmed_fresh',
                       reachability_status='REACHABLE', evidence_source='etw')
        expected_base = (10.0 * 0.2) + (1.0 * 10.0 * 0.5) + (10.0 * 0.3)  # 2 + 5 + 3 = 10
        assert result.base_score == pytest.approx(expected_base, abs=1e-6)

    def test_reachable_multiplier_is_one(self):
        result = score(reachability_status='REACHABLE', evidence_source='etw')
        assert result.reachability_multiplier == 1.0

    def test_unknown_multiplier_is_half(self):
        result = score(reachability_status='UNKNOWN', evidence_source='none')
        assert result.reachability_multiplier == 0.5

    def test_not_reachable_multiplier_is_point_05(self):
        result = score(reachability_status='NOT_REACHABLE', evidence_source='etw')
        assert result.reachability_multiplier == 0.05

    def test_final_score_is_base_times_multiplier(self):
        result = score(cvss=10.0, epss=1.0, is_kev=True, kev_status='confirmed_fresh',
                       reachability_status='REACHABLE', evidence_source='etw')
        # base = 10.0, multiplier = 1.0 → final = 10.0
        assert result.final_score == 10.0

    def test_kev_suppressed_when_not_reachable(self):
        # Even with KEV=true and CVSS=10, NOT_REACHABLE should suppress the score
        result = score(cvss=10.0, epss=1.0, is_kev=True, kev_status='confirmed_fresh',
                       reachability_status='NOT_REACHABLE', evidence_source='etw')
        assert result.final_score == pytest.approx(10.0 * 0.05, abs=0.01)

    def test_final_score_clamped_to_10(self):
        # Even if formula gives > 10, clamp it
        result = score(cvss=10.0, epss=1.0, is_kev=True, kev_status='confirmed_fresh',
                       reachability_status='REACHABLE', evidence_source='etw')
        assert result.final_score <= 10.0

    def test_final_score_not_negative(self):
        result = score(cvss=0.0, epss=0.0, is_kev=False,
                       reachability_status='NOT_REACHABLE', evidence_source='etw')
        assert result.final_score >= 0.0

    def test_contributions_sum_to_base(self):
        result = score(cvss=8.0, epss=0.6, is_kev=False, kev_status='confirmed_not_kev',
                       reachability_status='UNKNOWN', evidence_source='none')
        total = result.cvss_contrib + result.epss_contrib + result.kev_contrib
        assert total == pytest.approx(result.base_score, abs=1e-4)


# ─────────────────────────────────────────────────────────────────────────────
# Missing input handling
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingInputs:

    def test_cvss_none_uses_zero_in_formula(self):
        result_with = score(cvss=5.0, epss=0.0, is_kev=False)
        result_without = score(cvss=None, epss=0.0, is_kev=False)
        # Without CVSS the score should be lower
        assert result_without.final_score < result_with.final_score

    def test_cvss_none_recorded_as_none_in_inputs(self):
        result = score(cvss=None)
        assert result.cvss_input is None

    def test_epss_none_uses_zero_in_formula(self):
        result_with = score(epss=1.0, cvss=0.0, is_kev=False)
        result_without = score(epss=None, cvss=0.0, is_kev=False)
        assert result_without.final_score < result_with.final_score

    def test_epss_none_recorded_as_none_in_inputs(self):
        result = score(epss=None)
        assert result.epss_input is None

    def test_cvss_none_always_notes_it(self):
        result = score(cvss=None)
        assert any('CVSS' in n and ('missing' in n.lower() or 'unreachable' in n.lower())
                   for n in result.confidence_notes)

    def test_epss_none_always_notes_it(self):
        result = score(epss=None)
        assert any('EPSS' in n for n in result.confidence_notes)


# ─────────────────────────────────────────────────────────────────────────────
# Confidence levels
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidence:

    def test_etw_reachable_full_data_is_high(self):
        result = score(
            cvss=9.8, epss=0.97, is_kev=True,
            kev_status='confirmed_fresh',
            reachability_status='REACHABLE',
            evidence_source='etw',
        )
        assert result.confidence == 'high'

    def test_psutil_reachable_is_at_most_medium(self):
        result = score(
            cvss=9.8, epss=0.97, is_kev=True,
            kev_status='confirmed_fresh',
            reachability_status='REACHABLE',
            evidence_source='psutil',
        )
        assert result.confidence == 'medium'

    def test_unknown_reachability_is_low(self):
        result = score(
            cvss=9.8, epss=0.97, is_kev=True,
            kev_status='confirmed_fresh',
            reachability_status='UNKNOWN',
            evidence_source='etw',  # even ETW cannot raise confidence past 'low' when UNKNOWN
        )
        assert result.confidence == 'low'

    def test_missing_cvss_degrades_confidence_to_low(self):
        result = score(
            cvss=None,
            reachability_status='REACHABLE',
            evidence_source='etw',
        )
        assert result.confidence == 'low'

    def test_missing_epss_caps_confidence_at_medium(self):
        result = score(
            cvss=9.8,
            epss=None,
            is_kev=True,
            kev_status='confirmed_fresh',
            reachability_status='REACHABLE',
            evidence_source='etw',
        )
        # etw ceiling is 'high', but missing EPSS degrades to 'medium'
        assert result.confidence in ('low', 'medium')

    def test_stale_kev_caps_confidence_at_medium(self):
        result = score(
            cvss=9.8, epss=0.97, is_kev=True,
            kev_status='stale_present',
            reachability_status='REACHABLE',
            evidence_source='etw',
        )
        assert result.confidence in ('low', 'medium')

    def test_unavailable_kev_caps_confidence_at_medium(self):
        result = score(
            cvss=9.8, epss=0.97, is_kev=False,
            kev_status='unavailable',
            reachability_status='REACHABLE',
            evidence_source='etw',
        )
        assert result.confidence in ('low', 'medium')

    def test_no_evidence_source_is_low(self):
        result = score(evidence_source='none', reachability_status='REACHABLE')
        assert result.confidence == 'low'


# ─────────────────────────────────────────────────────────────────────────────
# Reason string content
# ─────────────────────────────────────────────────────────────────────────────

class TestReasonString:

    def test_reason_contains_cvss(self):
        result = score(cvss=9.8)
        assert '9.8' in result.reason

    def test_reason_contains_epss(self):
        result = score(epss=0.975)
        assert '0.975' in result.reason

    def test_reason_contains_kev_indicator(self):
        result_kev = score(is_kev=True, kev_status='confirmed_fresh')
        result_no_kev = score(is_kev=False, kev_status='confirmed_not_kev')
        assert '✓' in result_kev.reason
        assert '✗' in result_no_kev.reason

    def test_reason_contains_final_score(self):
        result = score(cvss=9.8, epss=0.97, is_kev=True, kev_status='confirmed_fresh',
                       reachability_status='REACHABLE', evidence_source='etw')
        assert str(result.final_score) in result.reason

    def test_reason_shows_na_for_missing_cvss(self):
        result = score(cvss=None)
        assert 'N/A' in result.reason

    def test_reason_shows_evidence_source(self):
        result = score(reachability_status='REACHABLE', evidence_source='psutil')
        assert 'psutil' in result.reason


# ─────────────────────────────────────────────────────────────────────────────
# Input recording (auditability invariant)
# ─────────────────────────────────────────────────────────────────────────────

class TestInputsAreRecorded:
    """
    Verify that every input is preserved verbatim in the output.
    This invariant ensures the DB row is self-contained for audit.
    """

    def test_all_inputs_recorded(self):
        result = score(
            cvss=7.5,
            epss=0.3,
            is_kev=True,
            kev_status='confirmed_fresh',
            reachability_status='REACHABLE',
            evidence_source='psutil',
        )
        assert result.cvss_input == 7.5
        assert result.epss_input == 0.3
        assert result.kev_input is True
        assert result.reachability_input == 'REACHABLE'
        assert result.evidence_source == 'psutil'

    def test_none_inputs_preserved_not_coerced(self):
        result = score(cvss=None, epss=None)
        assert result.cvss_input is None
        assert result.epss_input is None
