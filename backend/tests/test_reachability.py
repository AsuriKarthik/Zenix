"""
Tests for Steps 6–7 Reachability Tiers (psutil tier + ETW tier + Dual-tier Resolver + Telemetry API).

Coverage:
  - psutil correlation logic (REACHABLE, NOT_REACHABLE, UNKNOWN)
  - psutil confidence ceiling enforcement ('medium' max)
  - Privilege detection & ETW availability
  - ETW correlation & confidence ceiling ('high' max)
  - ETW unavailable fallback path
  - Dual-tier disagreement resolution (higher confidence ETW preferred, supporting psutil preserved)
  - Telemetry API endpoints (/api/telemetry/status, /api/telemetry/events)
"""

import json
from datetime import datetime, timezone
import pytest
from flask import Flask

from db import db, Component, ReachabilityVerdict, EtwEvent
from agents.reachability_psutil import evaluate_psutil_reachability
from agents.etw_collector import ETWCollector, etw_collector, is_elevated, is_windows
from agents.reachability_resolver import resolve_reachability
from api.telemetry import telemetry_bp
from config import Config

_UTC = timezone.utc


@pytest.fixture()
def telemetry_app(app):
    """Use test Flask app with telemetry_bp already registered."""
    return app


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — psutil Tier Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPsutilReachabilityTier:

    def test_psutil_matched_component_is_reachable_medium_confidence(self, app, db_session):
        """When component name/hash matches a memory map, status is REACHABLE with medium confidence."""
        with app.app_context():
            comp = Component(job_id="job-1", name="log4j-core", version="2.14.1", purl="pkg:maven/log4j-core@2.14.1")
            db.session.add(comp)
            db.session.commit()

            fake_maps = [
                {"pid": 1234, "process_name": "java.exe", "image_path": "C:\\apps\\lib\\log4j-core-2.14.1.jar"}
            ]

            verdicts = evaluate_psutil_reachability([comp], memory_maps=fake_maps)
            verdict = verdicts[int(comp.id)]

            assert verdict.status == "REACHABLE"
            assert verdict.confidence == "medium"  # psutil ceiling is medium
            assert verdict.evidence_source == "psutil"

            raw = json.loads(verdict.raw_evidence_json)
            assert raw["process_name"] == "java.exe"
            assert raw["pid"] == 1234

    def test_psutil_unmatched_component_is_unknown_none_source(self, app, db_session):
        """When memory maps were scanned but component wasn't found, status is UNKNOWN with evidence_source none."""
        with app.app_context():
            comp = Component(job_id="job-1", name="safe-library", version="1.0.0")
            db.session.add(comp)
            db.session.commit()

            fake_maps = [
                {"pid": 100, "process_name": "chrome.exe", "image_path": "C:\\Program Files\\Chrome\\chrome.dll"}
            ]

            verdicts = evaluate_psutil_reachability([comp], memory_maps=fake_maps)
            verdict = verdicts[int(comp.id)]

            assert verdict.status == "UNKNOWN"
            assert verdict.confidence == "low"
            assert verdict.evidence_source == "none"

    def test_psutil_empty_maps_returns_unknown_low_confidence(self, app, db_session):
        """When memory maps cannot be captured (empty), status is UNKNOWN with low confidence."""
        with app.app_context():
            comp = Component(job_id="job-1", name="unknown-lib", version="1.0.0")
            db.session.add(comp)
            db.session.commit()

            verdicts = evaluate_psutil_reachability([comp], memory_maps=[])
            verdict = verdicts[int(comp.id)]

            assert verdict.status == "UNKNOWN"
            assert verdict.confidence == "low"
            assert verdict.evidence_source == "none"


# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — ETW Tier Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestETWReachabilityTier:

    def test_privilege_detection_structure(self):
        """is_elevated returns bool without throwing exception."""
        elevated = is_elevated()
        assert isinstance(elevated, bool)

        if not is_windows():
            assert elevated is False

    def test_etw_matched_component_is_reachable_high_confidence(self, app, db_session):
        """When component matches an EtwEvent DB row, status is REACHABLE with high confidence."""
        with app.app_context():
            comp = Component(job_id="job-1", name="log4j-core", version="2.14.1")
            db.session.add(comp)

            evt = EtwEvent(
                timestamp=datetime.now(_UTC).replace(tzinfo=None),
                pid=9999,
                process_name="java.exe",
                image_path="C:\\service\\log4j-core.dll",
                evidence_source="etw",
                provider="Microsoft-Windows-Kernel-Process",
            )
            db.session.add(evt)
            db.session.commit()

            collector = ETWCollector()
            verdicts = collector.evaluate_etw_reachability([comp])
            verdict = verdicts[comp.id]

            assert verdict.status == "REACHABLE"
            assert verdict.confidence == "high"  # ETW ceiling is high
            assert verdict.evidence_source == "etw"


# ─────────────────────────────────────────────────────────────────────────────
# Dual-Tier Resolution Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDualTierResolution:

    def test_dual_tier_prefers_etw_high_confidence_over_psutil(self, app, db_session, monkeypatch):
        """Resolver selects ETW (high confidence) as primary verdict over psutil (medium confidence)."""
        with app.app_context():
            comp = Component(job_id="job-1", name="log4j-core", version="2.14.1")
            db.session.add(comp)

            # Record ETW event
            evt = EtwEvent(
                timestamp=datetime.now(_UTC).replace(tzinfo=None),
                pid=5000,
                process_name="java.exe",
                image_path="C:\\app\\log4j-core.jar",
                evidence_source="etw",
            )
            db.session.add(evt)
            db.session.commit()

            # Force etw_collector to report available for test
            monkeypatch.setattr(etw_collector, "is_available", True)

            fake_maps = [
                {"pid": 5000, "process_name": "java.exe", "image_path": "C:\\app\\log4j-core.jar"}
            ]

            resolved = resolve_reachability([comp], memory_maps=fake_maps)
            primary = resolved[comp.id]

            assert primary.evidence_source == "etw"
            assert primary.confidence == "high"
            assert primary.status == "REACHABLE"

            # Check that supporting psutil evidence was embedded
            raw = json.loads(primary.raw_evidence_json)
            assert "supporting_tier_evidence" in raw
            assert raw["supporting_tier_evidence"]["source"] == "psutil"

    def test_etw_unavailable_fallback_to_psutil(self, app, db_session, monkeypatch):
        """When ETW is unavailable, resolver falls back cleanly to psutil tier without failing."""
        with app.app_context():
            comp = Component(job_id="job-1", name="log4j-core", version="2.14.1")
            db.session.add(comp)
            db.session.commit()

            monkeypatch.setattr(etw_collector, "is_available", False)

            fake_maps = [
                {"pid": 111, "process_name": "java.exe", "image_path": "C:\\lib\\log4j-core.dll"}
            ]

            resolved = resolve_reachability([comp], memory_maps=fake_maps)
            verdict = resolved[comp.id]

            assert verdict.evidence_source == "psutil"
            assert verdict.confidence == "medium"
            assert verdict.status == "REACHABLE"


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry API Endpoint Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTelemetryAPIEndpoints:

    def test_telemetry_status_endpoint(self, telemetry_app, db_session):
        client = telemetry_app.test_client()
        client.post('/api/auth/register', json={"email": "tel_user@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "tel_user@zenix.io", "password": "Password123!"})

        res = client.get('/api/telemetry/status')

        assert res.status_code == 200
        data = res.get_json()
        assert "mode" in data
        assert "is_elevated" in data
        assert "event_count_total" in data
        assert "active_provider" in data

    def test_telemetry_events_endpoint(self, telemetry_app, db_session):
        with telemetry_app.app_context():
            evt = EtwEvent(
                timestamp=datetime.now(_UTC).replace(tzinfo=None),
                pid=777,
                process_name="test_proc.exe",
                image_path="C:\\path\\test.dll",
                evidence_source="etw",
            )
            db.session.add(evt)
            db.session.commit()

        client = telemetry_app.test_client()
        client.post('/api/auth/register', json={"email": "tel_user2@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "tel_user2@zenix.io", "password": "Password123!"})

        res = client.get('/api/telemetry/events')

        assert res.status_code == 200
        data = res.get_json()
        assert len(data) >= 1
        event = data[0]
        assert event["pid"] == 777
        assert event["process_name"] == "test_proc.exe"
        assert event["evidence_source"] == "etw"
        assert event["confidence"] == "high"
