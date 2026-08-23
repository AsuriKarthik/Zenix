"""
Unit tests for SBOM-driven Runtime Correlation Watchlist.

Verifies:
  1. Vulnerable watchlist construction from completed SBOM jobs.
  2. Strong identifier matching & version mismatch rejection.
  3. Runtime findings endpoint prioritizing correlated vulnerable component observations over normal telemetry noise.
"""

import json
from datetime import datetime, timezone
import pytest

from db import db, Job, Component, Vulnerability, EtwEvent, RiskScore
from agents.reachability_resolver import get_vulnerable_watchlist, correlate_event_with_watchlist


class TestWatchlistRuntimeCorrelation:

    def test_get_vulnerable_watchlist(self, app, db_session):
        with app.app_context():
            job = Job(sbom_format="CycloneDX", sbom_sha256="hash123", status="done")
            db.session.add(job)
            db.session.flush()

            comp = Component(job_id=job.id, name="log4j-core", version="2.14.1", purl="pkg:maven/log4j-core@2.14.1")
            db.session.add(comp)
            db.session.flush()

            vuln = Vulnerability(cve_id="CVE-2021-44228", component_id=comp.id, cvss=10.0, epss=0.95, is_kev=True)
            db.session.add(vuln)
            db.session.commit()

            watchlist = get_vulnerable_watchlist(job_id=job.id)
            assert len(watchlist) == 1
            assert watchlist[0]["name"] == "log4j-core"
            assert watchlist[0]["version"] == "2.14.1"
            assert len(watchlist[0]["vulnerabilities"]) == 1
            assert watchlist[0]["vulnerabilities"][0]["cve_id"] == "CVE-2021-44228"

    def test_correlate_event_with_watchlist_match_and_mismatch(self, app, db_session):
        watchlist = [{
            "component_id": 1,
            "job_id": "job-1",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/log4j-core@2.14.1",
            "file_hash": None,
            "vulnerabilities": [{
                "vulnerability_id": 10,
                "cve_id": "CVE-2021-44228",
                "cvss": 10.0,
                "epss": 0.95,
                "is_kev": True,
            }]
        }]

        # 1. Matching event
        match = correlate_event_with_watchlist(
            image_path="C:\\apps\\java\\lib\\log4j-core-2.14.1.jar",
            process_name="java.exe",
            image_hash=None,
            watchlist=watchlist
        )
        assert match is not None
        assert match["component_name"] == "log4j-core"
        assert match["cve_id"] == "CVE-2021-44228"

        # 2. Normal system DLL (unmatched)
        no_match = correlate_event_with_watchlist(
            image_path="C:\\Windows\\System32\\ntdll.dll",
            process_name="chrome.exe",
            image_hash=None,
            watchlist=watchlist
        )
        assert no_match is None

        # 3. Version mismatch rejection (openssl 3.2.0 vs 3.0.1 in watchlist)
        version_watchlist = [{
            "component_id": 2,
            "job_id": "job-1",
            "name": "openssl",
            "version": "3.0.1",
            "vulnerabilities": [{"cve_id": "CVE-2022-0778", "cvss": 7.5}]
        }]
        version_mismatch = correlate_event_with_watchlist(
            image_path="C:\\Program Files\\OpenSSL\\bin\\openssl-3.2.0.dll",
            process_name="openssl.exe",
            image_hash=None,
            watchlist=version_watchlist
        )
        assert version_mismatch is None

    def test_runtime_findings_endpoint_filters_out_normal_noise(self, app, db_session):
        client = app.test_client()

        # Register & Login
        client.post('/api/auth/register', json={"email": "analyst_corr@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "analyst_corr@zenix.io", "password": "Password123!"})

        with app.app_context():
            # Setup completed job with vulnerable component
            job = Job(sbom_format="CycloneDX", sbom_sha256="sha999", status="done", user_id=1)
            db.session.add(job)
            db.session.flush()

            comp = Component(job_id=job.id, name="log4j-core", version="2.14.1")
            db.session.add(comp)
            db.session.flush()

            vuln = Vulnerability(cve_id="CVE-2021-44228", component_id=comp.id, cvss=10.0)
            db.session.add(vuln)

            # Insert two raw ETW events: one normal (chrome), one matching (java)
            evt_normal = EtwEvent(
                image_path="C:\\Windows\\System32\\ntdll.dll",
                evidence_source="etw",
                pid=1000,
                process_name="chrome.exe"
            )
            evt_matched = EtwEvent(
                image_path="C:\\apps\\lib\\log4j-core-2.14.1.jar",
                evidence_source="etw",
                pid=2000,
                process_name="java.exe"
            )
            db.session.add_all([evt_normal, evt_matched])
            db.session.commit()

        # Query runtime findings
        res = client.get('/api/jobs/findings?finding_type=runtime')
        assert res.status_code == 200
        data = res.get_json()

        # Only 1 security finding generated (for log4j-core), normal chrome.exe ntdll load omitted!
        assert data["total"] == 1
        items = data["items"]
        assert len(items) == 1
        assert items[0]["cve_id"] == "CVE-2021-44228"
        assert items[0]["process_name"] == "java.exe"
        assert items[0]["pid"] == 2000
        assert items[0]["reachability_status"] == "REACHABLE"
