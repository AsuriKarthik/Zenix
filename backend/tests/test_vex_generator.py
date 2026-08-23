"""
Tests for Step 8 — CycloneDX VEX Generation & API.

Coverage:
  - Status mapping correctness:
      * NOT_REACHABLE (medium/high confidence) -> 'not_affected'
      * REACHABLE -> 'affected'
      * UNKNOWN -> 'under_investigation' (never collapses to 'not_affected')
  - HMAC-SHA256 signature generation & verification validity
  - End-to-end VEX document generation for completed jobs
  - Retrieval by job_id via /api/vex
  - Download endpoint /api/vex/<vex_id>/download returning signed CycloneDX JSON
"""

import json
from datetime import datetime, timezone
import pytest
import responses as resp_lib

from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, VexDocument, User
from pipeline.vex_generator import (
    generate_vex_documents_for_job,
    map_reachability_to_vex_status,
    sign_vex_document,
    verify_vex_signature,
    get_vex_keypair,
)
from jobs.queue import JobQueue
from config import Config
from tests.test_cve_matcher import OSV_LOG4J_RESPONSE, NVD_LOG4J_RESPONSE

_UTC = timezone.utc


# ─────────────────────────────────────────────────────────────────────────────
# Status Mapping & Signing Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVexStatusMappingAndSigning:

    def test_not_reachable_medium_confidence_maps_to_not_affected(self):
        status, just = map_reachability_to_vex_status('NOT_REACHABLE', 'medium')
        assert status == 'not_affected'
        assert just == 'vulnerable_code_not_in_execute_path'

    def test_not_reachable_high_confidence_maps_to_not_affected(self):
        status, just = map_reachability_to_vex_status('NOT_REACHABLE', 'high')
        assert status == 'not_affected'
        assert just == 'vulnerable_code_not_in_execute_path'

    def test_reachable_maps_to_affected(self):
        status, just = map_reachability_to_vex_status('REACHABLE', 'high')
        assert status == 'affected'

    def test_unknown_never_collapses_to_not_affected(self):
        """UNKNOWN status evaluates to under_investigation, never not_affected."""
        status, just = map_reachability_to_vex_status('UNKNOWN', 'low')
        assert status == 'under_investigation'
        assert status != 'not_affected'

    def test_hmac_signing_and_verification(self):
        doc_json = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4"})
        keypair = get_vex_keypair()
        sig = sign_vex_document(doc_json, keypair=keypair)

        assert isinstance(sig, str)
        assert len(sig) > 30  # Base64-encoded RSA signature string

        assert verify_vex_signature(doc_json, sig, keypair=keypair) is True
        assert verify_vex_signature(doc_json, "wrong-sig==", keypair=keypair) is False


# ─────────────────────────────────────────────────────────────────────────────
# VEX Document Generation & API Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVexGenerationPipeline:

    @resp_lib.activate
    def test_end_to_end_job_generates_signed_vex_documents(self, app, db_session, sample_sbom_bytes):
        """Completed job pipeline automatically generates signed VEX documents."""
        resp_lib.add(resp_lib.POST, f"{Config.OSV_API_BASE}/query", json=OSV_LOG4J_RESPONSE, status=200)
        resp_lib.add(resp_lib.GET, Config.NVD_API_BASE, json=NVD_LOG4J_RESPONSE, status=200)

        jq = JobQueue(app, sync_mode=True)
        job_id = jq.enqueue(sample_sbom_bytes, sbom_filename="sample.json")

        vex_docs = VexDocument.query.filter_by(job_id=job_id).all()
        assert len(vex_docs) >= 1

        doc = vex_docs[0]
        assert doc.vex_id.startswith("VEX-")
        assert doc.cve_id == "CVE-2021-44228"
        assert doc.status in ('not_affected', 'affected', 'under_investigation')
        assert doc.signature is not None
        assert len(doc.signature) > 30

        # Verify signature
        assert verify_vex_signature(doc.cyclonedx_vex_json, doc.signature) is True

    def test_vex_api_requires_login(self, app, db_session):
        """Unauthenticated requests to /api/vex receive 401."""
        client = app.test_client()
        res = client.get('/api/vex')
        assert res.status_code == 401

    def test_vex_api_retrieval_and_download_when_authenticated(self, app, db_session):
        """Logged-in user can query /api/vex and download raw CycloneDX VEX JSON."""
        client = app.test_client()
        res_reg = client.post('/api/auth/register', json={"email": "analyst@zenix.io", "password": "Password123!"})
        res_log = client.post('/api/auth/login', json={"email": "analyst@zenix.io", "password": "Password123!"})

        user_id = res_log.get_json()["user"]["id"]

        with app.app_context():
            job_abc = Job(id="job-abc", user_id=user_id, sbom_format="cyclonedx-json", sbom_sha256="123", status="done")
            db.session.add(job_abc)

            doc_json = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "vulnerabilities": []})
            sig = sign_vex_document(doc_json)

            vex_doc = VexDocument(
                job_id="job-abc",
                vex_id="VEX-2026-9999",
                cve_id="CVE-2021-44228",
                justification="vulnerable_code_not_in_execute_path",
                status="not_affected",
                evidence_summary="Tested",
                cyclonedx_vex_json=doc_json,
                signature=sig,
            )
            db.session.add(vex_doc)
            db.session.commit()

        # GET /api/vex?job_id=job-abc
        res = client.get('/api/vex?job_id=job-abc')
        assert res.status_code == 200
        data = res.get_json()
        assert len(data) == 1
        assert data[0]["vex_id"] == "VEX-2026-9999"
        assert data[0]["signature_valid"] is True

        # GET /api/vex/VEX-2026-9999/download
        res_dl = client.get('/api/vex/VEX-2026-9999/download')
        assert res_dl.status_code == 200
        assert res_dl.mimetype == "application/pdf"
        assert "VEX-2026-9999_VEX_Report.pdf" in res_dl.headers["Content-Disposition"]

    def test_generate_runtime_compliance_report_endpoint(self, app, db_session):
        """Authenticated user can POST /api/vex/generate-runtime-report."""
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "runtime_auditor@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "runtime_auditor@zenix.io", "password": "Password123!"})

        res = client.post('/api/vex/generate-runtime-report', json={"date": "today"})
        assert res.status_code == 201
        payload = res.get_json()
        assert "Live Telemetry Compliance Report successfully generated" in payload["message"]
        assert payload["source_type"] == "live_telemetry"
