"""
Tests for Zenix Architecture Redesign (Pillars 1–6).
"""

import json
import pytest
from datetime import datetime, timezone
from flask import Flask

from pipeline.cvss_calculator import calculate_cvss_base_score
from pipeline.enricher import enrich_cve, EnrichmentResult
from pipeline.scorer import compute_risk_score, ScoringResult
from api.telemetry import create_etw_session, is_valid_etw_session
from pipeline.vex_pdf_generator import generate_vex_pdf_bytes
from db import db, User, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, EtwEvent


def test_cvss_vector_base_score_derivation():
    """Verify CVSS v3.1 vector string calculation returns accurate base score."""
    # Critical vector
    vector_crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score, err = calculate_cvss_base_score(vector_crit)
    assert err is None
    assert score is not None
    assert 9.0 <= score <= 10.0

    # High vector
    vector_high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    score_h, err_h = calculate_cvss_base_score(vector_high)
    assert err_h is None
    assert score_h is not None
    assert 7.0 <= score_h <= 8.0

    # Invalid vector
    score_inv, err_inv = calculate_cvss_base_score("INVALID_VECTOR")
    assert score_inv is None
    assert "Unsupported" in err_inv or "invalid" in err_inv


def test_extended_unknown_reason_pattern():
    """Verify compute_risk_score generates explicit reasons and next actions when inputs are unknown."""
    scoring = compute_risk_score(
        cvss=None,
        epss=None,
        is_kev=False,
        kev_status='unavailable',
        reachability_status='UNKNOWN',
        evidence_source='none',
    )
    assert scoring.cvss_reason is not None
    assert "UNKNOWN" in scoring.cvss_reason
    assert scoring.cvss_next_action is not None

    assert scoring.epss_reason is not None
    assert "UNKNOWN" in scoring.epss_reason
    assert scoring.epss_next_action is not None

    assert scoring.kev_reason is not None
    assert "unavailable" in scoring.kev_reason.lower() or "unknown" in scoring.kev_reason.lower()
    assert scoring.kev_next_action is not None

    assert scoring.reachability_reason is not None
    assert "UNKNOWN" in scoring.reachability_reason
    assert scoring.reachability_next_action is not None

    assert scoring.evidence_source_reason is not None
    assert "NONE" in scoring.evidence_source_reason


def test_etw_short_lived_session_tokens():
    """Verify creation and expiration validation of short-lived ETW session tokens."""
    token, expires_at = create_etw_session(user_id=1, ip="127.0.0.1", ttl_minutes=30)
    assert token is not None
    assert len(token) >= 16
    assert is_valid_etw_session(token) is True
    assert is_valid_etw_session("invalid_token") is False


def test_vex_forensic_pdf_generation():
    """Verify VEX PDF report generates valid PDF bytes with forensic audit sections."""
    doc_data = {
        "vex_id": "ZX-VEX-TEST-100",
        "job_id": "ZX-JOB-100",
        "cve_id": "CVE-2026-1234",
        "component_name": "express",
        "component_version": "4.18.2",
        "purl": "pkg:npm/express@4.18.2",
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "evidence_summary": "ETW kernel image load trace: express binary not loaded in memory",
        "evidence_source": "etw",
        "cvss": 7.5,
        "cvss_version": "3.1",
        "cvss_severity": "HIGH",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_source": "NVD",
        "epss": 0.15,
        "epss_percentile": 0.92,
        "epss_source": "FIRST EPSS",
        "is_kev": False,
        "reachability_status": "NOT_REACHABLE",
        "reachability_reason": "No memory map or ETW ImageLoad event observed",
        "reachability_next_action": "Enable ETW collector and execute target binary",
        "cvss_contrib": 1.5,
        "epss_contrib": 0.75,
        "kev_contrib": 0.0,
        "base_score": 2.25,
        "reachability_multiplier": 0.05,
        "final_score": 0.11,
        "confidence": "HIGH",
        "reason": "CVSS 7.5 | EPSS 0.150 | KEV X | NOT_REACHABLE [etw] -> 0.11 (HIGH)",
        "description": "Test vulnerability description",
        "signature": "3044022011223344...",
        "signature_algorithm": "ECDSA P-256",
        "key_id": "zenix-ecdsa-key-1",
        "signature_valid": True,
    }

    pdf_bytes = generate_vex_pdf_bytes(doc_data)
    assert pdf_bytes is not None
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
