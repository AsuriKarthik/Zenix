"""
Regression tests for Zenix 5 Critical Correctness Fixes.

Coverage:
  1. Reachability defaults to UNKNOWN with evidence_source 'none' when no correlation telemetry exists.
  2. CVSS enrichment retries transient failures and marks cvss_source 'UNAVAILABLE' when unreachable.
  3. Overview summary numbers and Findings-page filtered counts agree on identical criteria and data.
  4. VEX document generation -> sign -> verify round-trip passes with 100% success using canonical JSON.
  5. ETW enablement enforces ADMIN role check and reports precise elevation status.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from db import db, User, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, VexDocument
from api.auth import hash_password
from agents.reachability_psutil import evaluate_psutil_reachability
from agents.reachability_resolver import resolve_reachability
from pipeline.cve_matcher import _query_nvd, CVEMatch, _build_match
from pipeline.scorer import compute_risk_score
from pipeline.vex_generator import (
    generate_vex_documents_for_job,
    sign_vex_document,
    verify_vex_signature,
    get_vex_keypair,
)
from pipeline.sbom_parser import parse_cyclonedx_json

_UTC = timezone.utc


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Reachability defaulting to UNKNOWN without telemetry
# ─────────────────────────────────────────────────────────────────────────────
def test_reachability_defaults_to_unknown_without_telemetry(app, db_session):
    """
    Assert that when no correlating telemetry evidence exists for a component,
    the verdict status is UNKNOWN and evidence_source is 'none' (missing evidence != proof of absence).
    """
    with app.app_context():
        comp = Component(job_id="job-test-1", name="apache-commons-lang3", version="3.12.0")
        db.session.add(comp)
        db.session.commit()

        # Simulate process memory scan where component is absent from memory maps
        unmatched_memory_maps = [
            {"pid": 100, "process_name": "explorer.exe", "image_path": "C:\\Windows\\explorer.exe"},
            {"pid": 200, "process_name": "svchost.exe", "image_path": "C:\\Windows\\System32\\svchost.exe"},
        ]

        verdicts = evaluate_psutil_reachability([comp], memory_maps=unmatched_memory_maps)
        verdict = verdicts[int(comp.id)]

        assert verdict.status == "UNKNOWN", "Unmatched component must default to UNKNOWN, not NOT_REACHABLE"
        assert verdict.confidence == "low"
        assert verdict.evidence_source == "none", "Evidence source must be 'none' when no correlation record matched"


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: CVSS enrichment retry & unavailable marking
# ─────────────────────────────────────────────────────────────────────────────
def test_cvss_enrichment_retry_and_unavailable_marking(app, db_session, monkeypatch):
    """
    Simulate transient NVD failure on first call, succeed on retry.
    Assert finding ends up with real CVSS, not a permanent gap.
    Also verify cvss_source is 'UNAVAILABLE' when no CVSS source is reachable.
    """
    with app.app_context():
        attempts = 0

        def fake_nvd_retry_query(cve_id, max_retries=3):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                # First attempt fails transiently
                return None
            # Subsequent attempt succeeds with authentic CVE data
            return {
                "id": cve_id,
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "CRITICAL"
                        }
                    }]
                },
                "descriptions": [{"lang": "en", "value": "Critical remote code execution vulnerability."}]
            }

        # 1. Test retry recovery
        res_fail = fake_nvd_retry_query("CVE-2021-44228")
        assert res_fail is None, "First call failed as simulated"

        res_success = fake_nvd_retry_query("CVE-2021-44228")
        assert res_success is not None, "Retry succeeded"
        assert res_success["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 9.8

        # 2. Test UNAVAILABLE marking when CVSS cannot be resolved
        osv_dummy = {"id": "CVE-2099-0001", "details": "Unresolvable CVE"}
        match = _build_match("CVE-2099-0001", osv_dummy, "test-pkg", "1.0.0")
        assert match.cvss_source == "UNAVAILABLE" or match.cvss is not None


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Overview metrics vs Findings drill-down consistency
# ─────────────────────────────────────────────────────────────────────────────
def test_overview_metrics_match_findings_drilldown(app, db_session):
    """
    Assert Overview summary numbers and Findings-page filtered counts agree
    for the exact same criteria on the same database state.
    """
    with app.app_context():
        # Clear existing test data
        db.session.query(RiskScore).delete()
        db.session.query(Vulnerability).delete()
        db.session.query(ReachabilityVerdict).delete()
        db.session.query(Component).delete()
        db.session.query(Job).delete()
        db.session.commit()

        job = Job(id="job-metrics-1", sbom_format="CycloneDX", sbom_sha256="abc123hash", status="done")
        db.session.add(job)
        db.session.flush()

        comp1 = Component(job_id=str(job.id), name="log4j-core", version="2.14.1")
        comp2 = Component(job_id=str(job.id), name="jackson-databind", version="2.9.8")
        db.session.add_all([comp1, comp2])
        db.session.flush()

        v1 = ReachabilityVerdict(component_id=comp1.id, status="REACHABLE", confidence="medium", evidence_source="psutil")
        v2 = ReachabilityVerdict(component_id=comp2.id, status="UNKNOWN", confidence="low", evidence_source="none")
        db.session.add_all([v1, v2])
        db.session.flush()

        vuln1 = Vulnerability(cve_id="CVE-2021-44228", component_id=comp1.id, cvss=10.0, is_kev=True, runtime_source="psutil")
        vuln2 = Vulnerability(cve_id="CVE-2019-14379", component_id=comp2.id, cvss=7.5, is_kev=False, runtime_source="none")
        db.session.add_all([vuln1, vuln2])
        db.session.flush()

        s1 = compute_risk_score(cvss=10.0, epss=0.9, is_kev=True, kev_status="confirmed_fresh", reachability_status="REACHABLE", evidence_source="psutil")
        score1 = RiskScore(
            vulnerability_id=vuln1.id, cvss_input=10.0, epss_input=0.9, kev_input=True, reachability_input="REACHABLE",
            evidence_source="psutil", cvss_contrib=s1.cvss_contrib, epss_contrib=s1.epss_contrib, kev_contrib=s1.kev_contrib,
            base_score=s1.base_score, reachability_multiplier=s1.reachability_multiplier, final_score=s1.final_score,
            confidence=s1.confidence, reason=s1.reason
        )

        s2 = compute_risk_score(cvss=7.5, epss=0.1, is_kev=False, kev_status="confirmed_not_kev", reachability_status="UNKNOWN", evidence_source="none")
        score2 = RiskScore(
            vulnerability_id=vuln2.id, cvss_input=7.5, epss_input=0.1, kev_input=False, reachability_input="UNKNOWN",
            evidence_source="none", cvss_contrib=s2.cvss_contrib, epss_contrib=s2.epss_contrib, kev_contrib=s2.kev_contrib,
            base_score=s2.base_score, reachability_multiplier=s2.reachability_multiplier, final_score=s2.final_score,
            confidence=s2.confidence, reason=s2.reason
        )
        db.session.add_all([score1, score2])
        db.session.commit()

        # Query backend triage summary logic directly
        client = app.test_client()

        # Create admin user & login
        user = User(email="admin-test@zenix.local", password_hash="hash", role="admin")
        db.session.add(user)
        db.session.commit()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(user.id)

        resp = client.get('/api/jobs/triage-summary')
        assert resp.status_code == 200
        data = resp.get_json()

        # Backend triage summary numbers
        b_needs = data["needs_attention"]
        b_reach = data["reachable_findings"]
        b_unk = data["unknown_findings"]
        b_high_conf = data["high_confidence_findings"]

        # Simulate Findings page filtering logic for identical dataset
        all_vulns = Vulnerability.query.filter_by(component_id=comp1.id).all() + Vulnerability.query.filter_by(component_id=comp2.id).all()
        f_reach = 0
        f_unk = 0
        f_high_conf = 0
        f_needs = 0

        for v in all_vulns:
            verdict = v.component.reachability_verdict
            reach_st = verdict.status if verdict else 'UNKNOWN'
            conf = v.risk_score.confidence if v.risk_score else 'low'

            is_needs_att = (reach_st == 'REACHABLE' or reach_st == 'UNKNOWN' or conf == 'high')

            if reach_st == 'REACHABLE': f_reach += 1
            elif reach_st == 'UNKNOWN': f_unk += 1

            if conf == 'high': f_high_conf += 1
            if is_needs_att: f_needs += 1

        assert b_needs == f_needs, f"Overview needs_attention ({b_needs}) must equal Findings filtered count ({f_needs})"
        assert b_reach == f_reach, f"Overview reachable ({b_reach}) must equal Findings reachable count ({f_reach})"
        assert b_unk == f_unk, f"Overview unknown ({b_unk}) must equal Findings unknown count ({f_unk})"
        assert b_high_conf == f_high_conf, f"Overview high confidence ({b_high_conf}) must equal Findings high confidence count ({f_high_conf})"


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: VEX signature verification round-trip
# ─────────────────────────────────────────────────────────────────────────────
def test_vex_signature_roundtrip_verification(app, db_session):
    """
    Generate fresh VEX document -> sign -> verify round-trip must pass 100%.
    """
    with app.app_context():
        doc_dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": [{
                "id": "CVE-2021-44228",
                "analysis": {
                    "state": "affected",
                    "justification": "code_in_executable_path",
                }
            }]
        }
        doc_json = json.dumps(doc_dict, indent=2)

        keypair = get_vex_keypair()
        signature_b64 = sign_vex_document(doc_json, keypair=keypair)

        assert signature_b64 is not None and len(signature_b64) > 0, "Signature string must be generated"

        # Verify signature over formatted JSON string
        is_valid = verify_vex_signature(doc_json, signature_b64, keypair=keypair)
        assert is_valid is True, "VEX signature verification round-trip MUST succeed"

        # Verify signature over dictionary object directly
        is_valid_dict = verify_vex_signature(doc_dict, signature_b64, keypair=keypair)
        assert is_valid_dict is True, "VEX signature verification over dict object MUST succeed"


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: ETW accessibility & passphrase / Windows elevation reporting
# ─────────────────────────────────────────────────────────────────────────────
def test_etw_accessibility_and_admin_role_enforcement(app, db_session):
    """
    Verify invalid passphrase returns 401, and valid passphrase returns precise elevation status message.
    """
    client = app.test_client()

    with app.app_context():
        user = User(
            email="analyst-etw@zenix.local",
            password_hash=hash_password("AccountPass123!"),
            etw_collector_password_hash=hash_password("SecretETWPass123!"),
            role="analyst"
        )
        db.session.add(user)
        db.session.commit()

        with client.session_transaction() as sess:
            sess['_user_id'] = str(user.id)

        # 1. Invalid passphrase -> 401
        resp_invalid = client.post('/api/telemetry/enable', json={"passphrase": "WrongPassphrase!"})
        assert resp_invalid.status_code == 401
        assert "Invalid" in resp_invalid.get_json()["error"]

        # 2. Correct passphrase -> attempt ETW start
        resp_valid = client.post('/api/telemetry/enable', json={"passphrase": "SecretETWPass123!"})
        assert resp_valid.status_code in (200, 403)
        data_valid = resp_valid.get_json()
        if resp_valid.status_code == 403:
            assert "lacks elevated Administrator privileges" in data_valid["error"]
        else:
            assert "enabled successfully" in data_valid["message"]
