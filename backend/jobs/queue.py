"""
JobQueue implementation — Python threading + DB persistence.

Implements the standard JobQueue interface:
  enqueue(raw_bytes, filename, user_id, job_type) -> job_id
  get_status(job_id) -> dict
  get_result(job_id) -> dict
  clean_stale_jobs(timeout_seconds) -> int

Worker threads pull jobs from an in-memory queue.Queue(), execute the pipeline runner
with Flask application context, and update status in SQLite at every stage transition.

Stale job recovery runs automatically at queue startup and can be invoked on demand.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from config import Config
from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore
from pipeline.sbom_parser import compute_sbom_sha256
from jobs.pipeline_runner import run_sbom_job

log = logging.getLogger(__name__)
def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class JobNotFoundError(KeyError):
    """Raised when a requested job_id does not exist in the database."""


class JobNotFinishedError(RuntimeError):
    """Raised when get_result is called on a job that is still queued or running."""


class JobQueue:
    """
    Thread-backed job queue with DB persistence and stale-job recovery.

    Args:
        app: Flask application instance.
        max_workers: Number of background worker threads to spin up.
        stale_timeout_seconds: Duration after which a 'running' job without an update is marked failed.
        sync_mode: If True, jobs execute synchronously on enqueue (useful for unit testing).
    """

    def __init__(self, app, max_workers: int = 2, stale_timeout_seconds: int = 300, sync_mode: bool = False):
        self.app = app
        self.max_workers = max_workers
        self.stale_timeout_seconds = stale_timeout_seconds
        self.sync_mode = sync_mode

        self._task_queue: queue.Queue[Tuple[str, bytes]] = queue.Queue()
        self._workers: list[threading.Thread] = []
        self._shutdown_event = threading.Event()

        # Create upload directory if missing
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

        # Cleanup any dangling running jobs from previous process lifetimes
        with self.app.app_context():
            self.clean_stale_jobs(timeout_seconds=self.stale_timeout_seconds)

        if not self.sync_mode:
            self._start_workers()

    def _start_workers(self) -> None:
        """Spawn worker threads."""
        for i in range(self.max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"zenix-job-worker-{i+1}", daemon=True)
            t.start()
            self._workers.append(t)
        log.info("Started %d job queue worker thread(s)", len(self._workers))

    def _worker_loop(self) -> None:
        """Worker main loop."""
        while not self._shutdown_event.is_set():
            try:
                job_id, sbom_bytes = self._task_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                run_sbom_job(self.app, job_id, sbom_bytes)
            except Exception as exc:
                log.exception("Unexpected error in worker loop processing job %s: %s", job_id, exc)
            finally:
                self._task_queue.task_done()

    def enqueue(
        self,
        sbom_bytes: bytes,
        sbom_filename: str = 'sbom.json',
        user_id: Optional[int] = None,
        job_type: str = 'sbom_analysis',
    ) -> str:
        """
        Enqueue a new SBOM processing job.

        Returns:
            job_id: UUID string assigned to the job.
        """
        job_id = str(uuid.uuid4())
        sha256_hash = compute_sbom_sha256(sbom_bytes)
        now = _utcnow()

        # Write copy of upload to storage
        filepath = os.path.join(Config.UPLOAD_FOLDER, f"{job_id}.json")
        with open(filepath, 'wb') as f:
            f.write(sbom_bytes)

        with self.app.app_context():
            job = Job(
                id=job_id,
                user_id=user_id,
                sbom_format='cyclonedx-json',
                sbom_sha256=sha256_hash,
                sbom_filename=sbom_filename,
                job_type=job_type,
                status='queued',
                submitted_at=now,
                updated_at=now,
            )
            db.session.add(job)
            db.session.commit()

        log.info("Enqueued job %s (sha256: %s)", job_id, sha256_hash[:12])

        if self.sync_mode:
            run_sbom_job(self.app, job_id, sbom_bytes)
        else:
            self._task_queue.put((job_id, sbom_bytes))

        return job_id

    def get_status(self, job_id: str) -> dict:
        """
        Get status of a job.

        Raises:
            JobNotFoundError: If job_id does not exist.
        """
        with self.app.app_context():
            job: Optional[Job] = db.session.get(Job, job_id)
            if not job:
                raise JobNotFoundError(f"Job '{job_id}' not found.")

            return {
                "job_id": job.id,
                "user_id": job.user_id,
                "job_type": job.job_type,
                "status": job.status,
                "sbom_format": job.sbom_format,
                "sbom_filename": job.sbom_filename,
                "sbom_sha256": job.sbom_sha256,
                "error_msg": job.error_msg,
                "component_count": job.component_count,
                "finding_count": job.finding_count,
                "submitted_at": job.submitted_at.isoformat() if job.submitted_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "updated_at": job.updated_at.isoformat() if job.updated_at else None,
            }

    def get_result(self, job_id: str) -> dict:
        """
        Get full results of a completed job.

        Raises:
            JobNotFoundError: If job_id does not exist.
            JobNotFinishedError: If job is still queued or running.
        """
        with self.app.app_context():
            job: Optional[Job] = db.session.get(Job, job_id)
            if not job:
                raise JobNotFoundError(f"Job '{job_id}' not found.")

            if job.status in ('queued', 'running'):
                raise JobNotFinishedError(
                    f"Job '{job_id}' is still in status '{job.status}'. Results not ready."
                )

            if job.status == 'failed':
                return {
                    "job_id": job.id,
                    "status": "failed",
                    "error_msg": job.error_msg,
                    "submitted_at": job.submitted_at.isoformat() if job.submitted_at else None,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                    "findings": [],
                }

            # Parse result summary json
            summary = json.loads(job.result_json) if job.result_json else {}

            # Fetch findings detail
            components = Component.query.filter_by(job_id=job.id).all()
            findings = []

            for comp in components:
                verdict = comp.reachability_verdict
                for vuln in comp.vulnerabilities:
                    score = vuln.risk_score
                    if not score:
                        continue

                    degradation_notes = json.loads(vuln.degradation_notes_json) if vuln.degradation_notes_json else []
                    confidence_notes = json.loads(score.confidence_notes_json) if score.confidence_notes_json else []

                    findings.append({
                        "vulnerability_id": vuln.id,
                        "cve_id": vuln.cve_id,
                        "component_name": comp.name,
                        "component_version": comp.version,
                        "purl": comp.purl,
                        "cvss": vuln.cvss,
                        "cvss_vector": vuln.cvss_vector,
                        "epss": vuln.epss,
                        "epss_percentile": vuln.epss_percentile,
                        "is_kev": vuln.is_kev,
                        "kev_status": vuln.kev_status,
                        "source": vuln.source,
                        "data_quality": vuln.data_quality,
                        "reachability_status": verdict.status if verdict else 'UNKNOWN',
                        "evidence_source": verdict.evidence_source if verdict else 'none',
                        "final_score": score.final_score,
                        "base_score": score.base_score,
                        "cvss_contrib": score.cvss_contrib,
                        "epss_contrib": score.epss_contrib,
                        "kev_contrib": score.kev_contrib,
                        "reachability_multiplier": score.reachability_multiplier,
                        "confidence": score.confidence,
                        "confidence_notes": confidence_notes,
                        "degradation_notes": degradation_notes,
                        "reason": score.reason,
                    })

            return {
                "job_id": job.id,
                "status": "done",
                "submitted_at": job.submitted_at.isoformat() if job.submitted_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "summary": summary,
                "findings": findings,
            }

    def clean_stale_jobs(self, timeout_seconds: Optional[int] = None) -> int:
        """
        Find any jobs in 'running' or 'queued' state with updated_at past timeout and mark them failed.

        Returns:
            Count of stale jobs recovered.
        """
        if timeout_seconds is None:
            timeout_seconds = self.stale_timeout_seconds

        cutoff = _utcnow() - timedelta(seconds=timeout_seconds)

        with self.app.app_context():
            stale_jobs = Job.query.filter(
                Job.status.in_(['running', 'queued']),
                Job.updated_at < cutoff
            ).all()

            count = len(stale_jobs)
            now = _utcnow()
            for j in stale_jobs:
                j.status = 'failed'
                j.error_msg = f"Job timed out or worker process terminated prior to completion (last update: {j.updated_at})."
                j.finished_at = now
                j.updated_at = now

            if count > 0:
                db.session.commit()
                log.warning("Recovered %d stale job(s) from dangling status", count)

            return count

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for queued jobs to complete (useful for tests)."""
        self._task_queue.join()

    def stop(self) -> None:
        """Stop worker threads."""
        self._shutdown_event.set()
        for t in self._workers:
            t.join(timeout=2.0)
