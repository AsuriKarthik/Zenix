"""
Unit tests for decoupled SBOM-driven runtime correlation, persistent runtime inventory,
threat judgment, reachability, identity confidence, and reconciliation engine.
"""

import pytest
from db import db, Job, Component, Vulnerability, EtwEvent, RuntimeInventory
from agents.reachability_resolver import (
    sync_runtime_inventory_from_telemetry,
    reconcile_runtime_inventory_with_sbom,
    resolve_component_identity,
    get_vulnerable_watchlist,
    correlate_event_with_watchlist,
)


class TestRuntimeInventoryCorrelation:

    def test_chrome_legitimate_software_drift(self, app, db_session):
        """Test Requirements 1, 3, 4, 9: Legitimate Chrome/Edge component inventory drift is NOT suspicious."""
        with app.app_context():
            obs = {
                "process_name": "chrome_elf.dll",
                "image_path": r"C:\Program Files\Google\Chrome\Application\chrome_elf.dll",
                "pid": 1868,
                "version": "120.0.0.0",
            }
            sync_runtime_inventory_from_telemetry(obs)

            item = RuntimeInventory.query.filter_by(process_name="chrome_elf.dll").first()
            assert item is not None
            assert item.drift_status == 'INVENTORY_DRIFT'
            assert item.finding_category == 'INVENTORY_DRIFT'

            conf, label = resolve_component_identity(r"C:\Program Files\Google\Chrome\Application\chrome_elf.dll", "chrome_elf.dll", "chrome_elf")
            assert conf == 'KNOWN'

    def test_unknown_component_handling(self, app, db_session):
        """Test Requirement 7: Unknown unverified component handling."""
        with app.app_context():
            obs = {
                "process_name": "unknown",
                "image_path": r"C:\Temp\unnamed.tmp",
                "pid": 9999,
            }
            sync_runtime_inventory_from_telemetry(obs)

            item = RuntimeInventory.query.filter_by(executable_path=r"C:\Temp\unnamed.tmp").first()
            assert item is not None
            assert item.drift_status == 'UNKNOWN_IDENTIFICATION_REQUIRED'
            assert item.finding_category == 'UNKNOWN_RUNTIME_COMPONENT'

            conf, label = resolve_component_identity(r"C:\Temp\unnamed.tmp", "unknown", "unknown")
            assert conf == 'UNKNOWN'

    def test_versioned_sbom_and_reconciliation(self, app, db_session):
        """Test Requirements 10 & 14: Uploading SBOM v2 reconciles previously detected inventory drift."""
        with app.app_context():
            # Day 1: Telemetry detects NewSoftware.exe before SBOM v1 is uploaded
            obs = {
                "process_name": "NewSoftware.exe",
                "image_path": r"C:\Program Files\NewSoftware\NewSoftware.exe",
                "pid": 1234,
            }
            sync_runtime_inventory_from_telemetry(obs)

            item_before = RuntimeInventory.query.filter_by(process_name="NewSoftware.exe").first()
            assert item_before.drift_status == 'INVENTORY_DRIFT'

            # Day 2: Upload SBOM v2 containing NewSoftware
            job_v2 = Job(
                id="job-v2-test",
                sbom_format="CycloneDX",
                sbom_sha256="sha256v2",
                sbom_filename="sbom_v2.json",
                status="done",
                sbom_version_tag="v2",
            )
            db.session.add(job_v2)
            db.session.commit()

            comp = Component(
                job_id="job-v2-test",
                name="NewSoftware",
                version="1.0.0",
            )
            db.session.add(comp)
            db.session.commit()

            # Execute Reconciliation
            resolved_count = reconcile_runtime_inventory_with_sbom("job-v2-test")
            assert resolved_count >= 1

            item_after = RuntimeInventory.query.filter_by(process_name="NewSoftware.exe").first()
            assert item_after.drift_status == 'DRIFT_RESOLVED'
            assert item_after.matched_sbom_component_id == comp.id

    def test_classification_matrix_cases(self, app, db_session):
        """Test Requirement 12: Real vulnerability detection remains active."""
        with app.app_context():
            # Create completed SBOM baseline with vulnerable OpenSSL
            job = Job(id="job-baseline", sbom_format="CycloneDX", sbom_sha256="sha123", status="done", sbom_version_tag="v1")
            db.session.add(job)
            db.session.commit()

            openssl_comp = Component(job_id="job-baseline", name="OpenSSL", version="3.0.0")
            db.session.add(openssl_comp)
            db.session.commit()

            vuln = Vulnerability(cve_id="CVE-2026-1111", component_id=openssl_comp.id, cvss=8.8, epss=0.25, is_kev=True)
            db.session.add(vuln)
            db.session.commit()

            watchlist = get_vulnerable_watchlist(job_id="job-baseline")
            assert len(watchlist) == 1

            # Case C: SBOM = YES, Runtime = YES, Vulnerability = YES
            matched = correlate_event_with_watchlist(
                image_path=r"C:\App\openssl.dll",
                process_name="App.exe",
                image_hash=None,
                watchlist=watchlist
            )
            assert matched is not None
            assert matched["cve_id"] == "CVE-2026-1111"
