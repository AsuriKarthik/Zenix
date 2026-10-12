"""
Jobs API Endpoints — Requirement 6 (Upload Limits & Sanity Pre-Validation) + Requirement 7 (Strict Data Isolation).

Endpoints:
  POST /api/jobs/upload — upload SBOM file and enqueue analysis job (pre-validated, max 10MB).
  GET /api/jobs — list jobs for authenticated user (strictly user-isolated unless admin).
  GET /api/jobs/<job_id>/status — get status of a job (strictly user-isolated unless admin).
  GET /api/jobs/<job_id>/result — get full findings & scores of a completed job (user-isolated).
"""

from __future__ import annotations

import json
import logging
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from config import Config
from db import db, Job
from jobs.queue import JobQueue, JobNotFoundError, JobNotFinishedError
from pipeline.sbom_parser import parse_cyclonedx_json, SBOMParseError

jobs_bp = Blueprint('jobs', __name__, url_prefix='/api/jobs')
log = logging.getLogger(__name__)

# Global job queue reference initialized by app
_job_queue: JobQueue | None = None


def init_jobs_api(job_queue: JobQueue) -> None:
    """Bind JobQueue instance to jobs API."""
    global _job_queue
    _job_queue = job_queue


def get_job_queue() -> JobQueue:
    if _job_queue is None:
        raise RuntimeError("JobQueue has not been initialized on jobs API blueprint.")
    return _job_queue


@jobs_bp.route('/upload', methods=['POST'])
@login_required
def upload_sbom():
    """
    Upload CycloneDX JSON SBOM file and enqueue analysis job.
    Enforces Requirement 6:
      - Max file payload: 10 MB (enforced at Flask MAX_CONTENT_LENGTH and byte check).
      - Sanity & pre-validation: Filename .json check, valid JSON syntax, and CycloneDX structure check.
    """
    if 'file' in request.files:
        uploaded_file = request.files['file']
        filename = uploaded_file.filename or 'sbom.json'
        sbom_bytes = uploaded_file.read()
    else:
        sbom_bytes = request.get_data()
        filename = request.headers.get('X-File-Name', 'sbom.json')

    if not sbom_bytes:
        return jsonify({"error": "No SBOM file or payload provided."}), 400

    # 1. Size Limit Check (Requirement 6)
    max_bytes = getattr(Config, 'MAX_SBOM_SIZE_BYTES', 10 * 1024 * 1024)
    if len(sbom_bytes) > max_bytes:
        return jsonify({
            "error": f"File payload exceeds maximum allowed size of {max_bytes // (1024 * 1024)} MB."
        }), 413

    # 2. Extension Check (Requirement 6)
    if filename and not filename.lower().endswith('.json'):
        return jsonify({
            "error": f"Unsupported file type '{filename}'. Only CycloneDX JSON files (.json) are supported."
        }), 400

    # 3. Pre-validation & Sanity Check (Requirement 6)
    try:
        # Pre-parse SBOM in API layer before creating job or queuing
        parse_cyclonedx_json(sbom_bytes)
    except SBOMParseError as err:
        log.warning("Rejected invalid SBOM upload from user %s: %s", current_user.id, err)
        return jsonify({"error": f"Invalid SBOM format: {err}"}), 400
    except Exception as err:
        log.warning("Malformed JSON upload from user %s: %s", current_user.id, err)
        return jsonify({"error": f"Uploaded file is not valid JSON: {err}"}), 400

    # 4. Enqueue Job with Authenticated User ID (Requirement 7)
    jq = get_job_queue()
    job_id = jq.enqueue(
        sbom_bytes=sbom_bytes,
        sbom_filename=filename,
        user_id=current_user.id if current_user.is_authenticated else None,
        job_type='sbom_analysis',
    )

    return jsonify({
        "message": "SBOM uploaded and pre-validated successfully.",
        "job_id": job_id,
        "status": "queued",
    }), 202


@jobs_bp.route('', methods=['GET'])
@login_required
def list_jobs():
    """
    List jobs.
    Enforces Requirement 7: Analysts can ONLY see their own jobs. Admins see all jobs.
    """
    if current_user.role == 'admin':
        jobs = Job.query.order_by(db.desc(Job.submitted_at)).limit(100).all()
    else:
        jobs = Job.query.filter_by(user_id=current_user.id).order_by(db.desc(Job.submitted_at)).all()

    results = []
    for j in jobs:
        results.append({
            "job_id": j.id,
            "user_id": j.user_id,
            "sbom_filename": j.sbom_filename,
            "sbom_sha256": j.sbom_sha256,
            "status": j.status,
            "component_count": j.component_count,
            "finding_count": j.finding_count,
            "submitted_at": j.submitted_at.isoformat() if j.submitted_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        })

    return jsonify(results), 200


@jobs_bp.route('/<job_id>/status', methods=['GET'])
@login_required
def get_job_status(job_id: str):
    """
    Get status of a job by ID.
    Enforces Requirement 7: Analysts can ONLY view their own jobs.
    """
    jq = get_job_queue()
    try:
        status_info = jq.get_status(job_id)

        # Authorization Check (Requirement 7)
        if current_user.role != 'admin' and status_info.get('user_id') and status_info['user_id'] != current_user.id:
            return jsonify({"error": "Unauthorized access to job."}), 403

        return jsonify(status_info), 200
    except JobNotFoundError as err:
        return jsonify({"error": str(err)}), 404


@jobs_bp.route('/<job_id>/result', methods=['GET'])
@login_required
def get_job_result(job_id: str):
    """
    Get full analysis results of a completed job.
    Enforces Requirement 7: Analysts can ONLY view their own job results.
    """
    jq = get_job_queue()
    try:
        status_info = jq.get_status(job_id)

        # Authorization Check (Requirement 7)
        if current_user.role != 'admin' and status_info.get('user_id') and status_info['user_id'] != current_user.id:
            return jsonify({"error": "Unauthorized access to job result."}), 403

        result = jq.get_result(job_id)
        return jsonify(result), 200
    except JobNotFoundError as err:
        return jsonify({"error": str(err)}), 404
    except JobNotFinishedError as err:
        return jsonify({"error": str(err), "status": "pending"}), 202
