"""
Tests for jobs/queue.py and pipeline_runner.py

Coverage:
  - Enqueue and synchronous execution
  - Async thread worker pool execution
  - Status reporting & transitions
  - Result retrieval and structured output
  - JobNotFoundError and JobNotFinishedError handling
  - Pipeline failure (malformed SBOM / parse error) handling
  - Stale job recovery (timed out 'running' job converted to 'failed')
"""

import time
from datetime import datetime, timezone, timedelta
import pytest
import responses as resp_lib

from db import db, Job
from jobs.queue import JobQueue, JobNotFoundError, JobNotFinishedError
from config import Config
from tests.test_cve_matcher import OSV_LOG4J_RESPONSE, NVD_LOG4J_RESPONSE, OSV_EMPTY_RESPONSE

_UTC = timezone.utc


# ─────────────────────────────────────────────────────────────────────────────
# Synchronous Mode Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestJobQueueSyncMode:

    @resp_lib.activate
    def test_enqueue_runs_pipeline_to_completion(self, app, db_session, sample_sbom_bytes):
        """Enqueueing a valid SBOM in sync_mode executes the pipeline immediately."""
        # Mock OSV & NVD calls for log4j-core and other components
        resp_lib.add(resp_lib.POST, f"{Config.OSV_API_BASE}/query", json=OSV_LOG4J_RESPONSE, status=200)
        resp_lib.add(resp_lib.GET, Config.NVD_API_BASE, json=NVD_LOG4J_RESPONSE, status=200)

        jq = JobQueue(app, sync_mode=True)
        job_id = jq.enqueue(sample_sbom_bytes, sbom_filename="sample_sbom.json")

        status_info = jq.get_status(job_id)
        assert status_info["status"] == "done"
        assert status_info["component_count"] == 4
        assert status_info["finding_count"] >= 1
        assert status_info["finished_at"] is not None

        result_info = jq.get_result(job_id)
        assert result_info["status"] == "done"
        assert len(result_info["findings"]) >= 1

        finding = result_info["findings"][0]
        assert finding["cve_id"] == "CVE-2021-44228"
        assert finding["reachability_status"] in ("NOT_REACHABLE", "REACHABLE", "UNKNOWN")
        assert finding["evidence_source"] in ("psutil", "etw", "none")
        assert finding["confidence"] in ("low", "medium", "high")
        assert "final_score" in finding
        assert "reason" in finding

    def test_malformed_sbom_fails_job_with_detailed_error(self, app, db_session):
        """Malformed JSON causes job to fail with SBOMParseError in error_msg."""
        jq = JobQueue(app, sync_mode=True)
        bad_bytes = b"not a json document"

        job_id = jq.enqueue(bad_bytes, sbom_filename="bad.json")

        status_info = jq.get_status(job_id)
        assert status_info["status"] == "failed"
        assert "SBOM Parse Error" in status_info["error_msg"]

        result_info = jq.get_result(job_id)
        assert result_info["status"] == "failed"
        assert "SBOM Parse Error" in result_info["error_msg"]

    def test_spdx_sbom_fails_job_with_helpful_message(self, app, db_session):
        """SPDX format causes job to fail with helpful error message."""
        jq = JobQueue(app, sync_mode=True)
        spdx_bytes = b'{"bomFormat": "SPDX", "specVersion": "2.3"}'

        job_id = jq.enqueue(spdx_bytes, sbom_filename="spdx.json")

        status_info = jq.get_status(job_id)
        assert status_info["status"] == "failed"
        assert "SPDX format is not supported" in status_info["error_msg"]


# ─────────────────────────────────────────────────────────────────────────────
# Asynchronous Thread Pool Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestJobQueueAsyncMode:

    @resp_lib.activate
    def test_async_worker_pool_executes_job(self, app, db_session, minimal_sbom_bytes):
        """Worker thread picks up job from queue and completes it asynchronously."""
        resp_lib.add(resp_lib.POST, f"{Config.OSV_API_BASE}/query", json=OSV_EMPTY_RESPONSE, status=200)

        jq = JobQueue(app, max_workers=1, sync_mode=False)
        try:
            job_id = jq.enqueue(minimal_sbom_bytes, sbom_filename="minimal.json")

            # Wait for queue worker to finish
            jq.join(timeout=5.0)

            status_info = jq.get_status(job_id)
            assert status_info["status"] == "done"
            assert status_info["component_count"] == 1
        finally:
            jq.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Exception & Edge Case Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestJobQueueExceptionsAndRecovery:

    def test_get_status_invalid_id_raises_job_not_found(self, app, db_session):
        jq = JobQueue(app, sync_mode=True)
        with pytest.raises(JobNotFoundError, match="Job 'bogus-id' not found"):
            jq.get_status("bogus-id")

    def test_get_result_invalid_id_raises_job_not_found(self, app, db_session):
        jq = JobQueue(app, sync_mode=True)
        with pytest.raises(JobNotFoundError, match="Job 'bogus-id' not found"):
            jq.get_result("bogus-id")

    def test_get_result_running_job_raises_job_not_finished(self, app, db_session):
        """Calling get_result on a running or queued job raises JobNotFinishedError."""
        with app.app_context():
            job = Job(
                id="running-job-123",
                user_id=None,
                sbom_format="cyclonedx-json",
                sbom_sha256="abc",
                status="running",
                submitted_at=datetime.now(_UTC),
                updated_at=datetime.now(_UTC),
            )
            db.session.add(job)
            db.session.commit()

        jq = JobQueue(app, sync_mode=True)
        with pytest.raises(JobNotFinishedError, match="still in status 'running'"):
            jq.get_result("running-job-123")

    def test_clean_stale_jobs_marks_dangling_running_jobs_failed(self, app, db_session):
        """Jobs stuck in 'running' state past the timeout are marked failed."""
        jq = JobQueue(app, sync_mode=True, stale_timeout_seconds=300)

        stale_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10)

        with app.app_context():
            stale_job = Job(
                id="stale-job-999",
                user_id=None,
                sbom_format="cyclonedx-json",
                sbom_sha256="abc",
                status="running",
                submitted_at=stale_time,
                started_at=stale_time,
                updated_at=stale_time,
            )
            db.session.add(stale_job)
            db.session.commit()

        recovered_count = jq.clean_stale_jobs(timeout_seconds=300)
        assert recovered_count == 1

        status_info = jq.get_status("stale-job-999")
        assert status_info["status"] == "failed"
        assert "timed out" in status_info["error_msg"]
