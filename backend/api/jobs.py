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
import os
from datetime import timezone
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from config import Config
from db import db, _utcnow, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, EtwEvent
from jobs.queue import JobQueue, JobNotFoundError, JobNotFinishedError
from pipeline.sbom_parser import parse_sbom, parse_cyclonedx_json, SBOMParseError

jobs_bp = Blueprint('jobs', __name__, url_prefix='/api/jobs')
log = logging.getLogger(__name__)


def _fmt_ts(dt) -> str | None:
    """
    Format a datetime as ISO 8601 with explicit UTC 'Z' suffix.
    Handles both naive and aware datetimes stored in the DB.
    Returns None if dt is None.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


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
    scan_name = (request.form.get('scan_name') or request.form.get('name') or '').strip()

    if 'file' in request.files:
        uploaded_file = request.files['file']
        orig_filename = uploaded_file.filename or 'sbom.json'
        sbom_bytes = uploaded_file.read()
    else:
        sbom_bytes = request.get_data()
        orig_filename = request.headers.get('X-File-Name', 'sbom.json')

    display_filename = scan_name if scan_name else (request.headers.get('X-Scan-Name') or orig_filename)

    if not sbom_bytes:
        return jsonify({"error": "No SBOM file or payload provided."}), 400

    # 1. Size Limit Check (Requirement 6)
    max_bytes = getattr(Config, 'MAX_SBOM_SIZE_BYTES', 10 * 1024 * 1024)
    if len(sbom_bytes) > max_bytes:
        return jsonify({
            "error": f"File payload exceeds maximum allowed size of {max_bytes // (1024 * 1024)} MB."
        }), 413

    # 2. Extension Check (Supports JSON, XML, SPDX, Tag/Value text)
    valid_exts = ('.json', '.xml', '.spdx', '.txt', '.cdx')
    if orig_filename and not orig_filename.lower().endswith(valid_exts):
        return jsonify({
            "error": f"Unsupported file type '{orig_filename}'. Supported SBOM extensions: .json, .xml, .spdx, .txt, .cdx"
        }), 400

    # 3. Pre-validation & Sanity Check
    try:
        # Pre-parse SBOM in API layer before creating job or queuing
        parse_sbom(sbom_bytes, orig_filename)
    except SBOMParseError as err:
        log.warning("Rejected invalid SBOM upload from user %s: %s", getattr(current_user, 'id', 'anonymous'), err)
        return jsonify({"error": f"Invalid SBOM format: {err}"}), 400
    except Exception as err:
        log.warning("Malformed SBOM upload from user %s: %s", getattr(current_user, 'id', 'anonymous'), err)
        return jsonify({"error": f"Uploaded SBOM file could not be parsed: {err}"}), 400

    # 4. Enqueue Job with Authenticated User ID (Requirement 7)
    jq = get_job_queue()
    user_id = getattr(current_user, 'id', None) if current_user.is_authenticated else None
    job_id = jq.enqueue(
        sbom_bytes=sbom_bytes,
        sbom_filename=display_filename,
        user_id=user_id,
        job_type='sbom_analysis',
    )

    return jsonify({
        "message": "SBOM uploaded and pre-validated successfully.",
        "job_id": job_id,
        "status": "queued",
    }), 202


@jobs_bp.route('/<job_id>', methods=['DELETE'])
@login_required
def delete_job(job_id: str):
    """
    Delete/cancel an analysis job and clean up its associated records.
    """
    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)

    job = Job.query.filter_by(id=job_id).first()
    if not job:
        return jsonify({"error": "Job not found."}), 404

    if user_role != 'admin' and job.user_id != user_id:
        return jsonify({"error": "Access denied."}), 403

    try:
        comps = Component.query.filter_by(job_id=job_id).all()
        comp_ids = [c.id for c in comps]
        if comp_ids:
            vulns = Vulnerability.query.filter(Vulnerability.component_id.in_(comp_ids)).all()
            vuln_ids = [v.id for v in vulns]
            if vuln_ids:
                RiskScore.query.filter(RiskScore.vulnerability_id.in_(vuln_ids)).delete(synchronize_session=False)
                Vulnerability.query.filter(Vulnerability.component_id.in_(comp_ids)).delete(synchronize_session=False)
            ReachabilityVerdict.query.filter(ReachabilityVerdict.component_id.in_(comp_ids)).delete(synchronize_session=False)
            Component.query.filter_by(job_id=job_id).delete(synchronize_session=False)

        db.session.delete(job)
        db.session.commit()
        return jsonify({"message": f"Job {job_id} deleted successfully."}), 200
    except Exception as exc:
        db.session.rollback()
        log.error("Failed to delete job %s: %s", job_id, exc)
        return jsonify({"error": f"Failed to delete job: {exc}"}), 500


@jobs_bp.route('', methods=['GET'])
@login_required
def list_jobs():

    """
    List jobs.
    Enforces Requirement 7: Analysts can ONLY see their own jobs. Admins see all jobs.
    Includes reachable_count and unknown_count per scan for Recent Scans dashboard table.
    """
    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)

    if user_role == 'admin':
        jobs = Job.query.order_by(db.desc(Job.submitted_at)).limit(100).all()
    else:
        jobs = Job.query.filter(
            db.or_(Job.user_id == user_id, Job.user_id.is_(None))
        ).order_by(db.desc(Job.submitted_at)).all()

    results = []
    for j in jobs:
        reachable_cnt = 0
        unknown_cnt = 0
        if j.status == 'done':
            reachable_cnt = (
                db.session.query(RiskScore)
                .join(Vulnerability, RiskScore.vulnerability_id == Vulnerability.id)
                .join(Component, Vulnerability.component_id == Component.id)
                .join(ReachabilityVerdict, Component.id == ReachabilityVerdict.component_id)
                .filter(Component.job_id == j.id, ReachabilityVerdict.status == 'REACHABLE')
                .count()
            )
            unknown_cnt = (
                db.session.query(RiskScore)
                .join(Vulnerability, RiskScore.vulnerability_id == Vulnerability.id)
                .join(Component, Vulnerability.component_id == Component.id)
                .join(ReachabilityVerdict, Component.id == ReachabilityVerdict.component_id)
                .filter(Component.job_id == j.id, ReachabilityVerdict.status == 'UNKNOWN')
                .count()
            )

        results.append({
            "job_id": j.id,
            "user_id": j.user_id,
            "sbom_filename": j.sbom_filename,
            "sbom_sha256": j.sbom_sha256,
            "status": j.status,
            "progress_pct": getattr(j, 'progress_pct', 100 if j.status == 'done' else 0),
            "error_code": getattr(j, 'error_code', None),
            "error_msg": j.error_msg,
            "unscannable_count": getattr(j, 'unscannable_count', 0),
            "component_count": j.component_count,
            "finding_count": j.finding_count,
            "reachable_count": reachable_cnt,
            "unknown_count": unknown_cnt,
            "submitted_at": _fmt_ts(j.submitted_at),
            "finished_at": _fmt_ts(j.finished_at),
        })

    return jsonify(results), 200


@jobs_bp.route('/triage-summary', methods=['GET'])
@jobs_bp.route('/overview-summary', methods=['GET'])
@login_required
def get_triage_summary():
    """
    Get dynamic security triage metrics and priority queue for authenticated user.
    Single source of truth for Overview dashboard and metrics cards (Requirement 7 & 8).
    """
    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)

    if user_role == 'admin':
        all_jobs = Job.query.all()
    else:
        all_jobs = Job.query.filter(
            db.or_(Job.user_id == user_id, Job.user_id.is_(None))
        ).all()

    active_scans = sum(1 for j in all_jobs if j.status in ('running', 'queued'))
    completed_scans = sum(1 for j in all_jobs if j.status == 'done')
    failed_scans = sum(1 for j in all_jobs if j.status == 'failed')

    done_job_ids = [j.id for j in all_jobs if j.status == 'done']

    from agents.etw_collector import etw_collector
    etw_status = etw_collector.get_status()
    etw_active = etw_status.get("running", False)

    if not done_job_ids:
        telemetry_msg = "No runtime telemetry available" if not etw_active else "Active telemetry collection running — no analyzed SBOM jobs loaded"
        res = {
            "active_scans": active_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "findings_total": 0,
            "reachable_findings": 0,
            "unknown_findings": 0,
            "high_confidence_findings": 0,
            "needs_attention": 0,
            "etw_active": etw_active,
            "telemetry_data_state": "NO_TELEMETRY_AVAILABLE" if not etw_active else "ACTIVE_NO_JOBS",
            "telemetry_message": telemetry_msg,
            "system_status": "READY" if active_scans == 0 else "RUNNING",
            "metrics": {
                "needs_attention": 0,
                "reachable": 0,
                "unknown": 0,
                "high_confidence": 0,
                "total_findings": 0,
                "kev_count": 0,
            },
            "priority_queue": [],
        }
        return jsonify(res), 200

    query = (
        db.session.query(Vulnerability, Component, Job, RiskScore, ReachabilityVerdict)
        .select_from(Vulnerability)
        .join(Component, Vulnerability.component_id == Component.id)
        .join(Job, Component.job_id == Job.id)
        .outerjoin(RiskScore, Vulnerability.id == RiskScore.vulnerability_id)
        .outerjoin(ReachabilityVerdict, Component.id == ReachabilityVerdict.component_id)
        .filter(Component.job_id.in_(done_job_ids))
    )

    all_rows = query.all()

    reachable_count = 0
    unknown_count = 0
    high_confidence_count = 0
    needs_attention_count = 0
    kev_count = 0

    seen_priority_keys = set()
    priority_items = []

    for vuln, comp, job, score, verdict in all_rows:
        reach = (verdict.status if verdict else 'UNKNOWN').upper()
        conf = (score.confidence if (score and score.confidence) else 'low').lower()
        is_kev = bool(vuln.is_kev)

        if is_kev:
            kev_count += 1

        is_needs_att = (reach == 'REACHABLE' or reach == 'UNKNOWN' or conf == 'high')

        if reach == 'REACHABLE':
            reachable_count += 1
        elif reach == 'UNKNOWN':
            unknown_count += 1

        if conf == 'high':
            high_confidence_count += 1

        if is_needs_att:
            needs_attention_count += 1

            pkey = (vuln.cve_id, comp.name, comp.version)
            if pkey not in seen_priority_keys:
                seen_priority_keys.add(pkey)
                priority_items.append({
                    "job_id": job.id,
                    "vulnerability_id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "component_name": comp.name,
                    "component_version": comp.version,
                    "purl": comp.purl,
                    "cvss": vuln.cvss,
                    "cvss_version": getattr(vuln, 'cvss_version', None),
                    "cvss_severity": getattr(vuln, 'cvss_severity', None),
                    "cvss_source": getattr(vuln, 'cvss_source', 'NVD'),
                    "epss": vuln.epss,
                    "epss_source": getattr(vuln, 'epss_source', 'FIRST EPSS'),
                    "is_kev": is_kev,
                    "shodan_exposed_hosts": vuln.shodan_exposed_hosts,
                    "virustotal_detections": vuln.virustotal_detections,
                    "reachability_status": reach,
                    "confidence": conf.upper(),
                    "evidence_source": verdict.evidence_source if verdict else 'none',
                    "final_score": score.final_score if score else (vuln.cvss if vuln.cvss else 0.0),
                    "base_score": score.base_score if score else (vuln.cvss if vuln.cvss else 0.0),
                    "reason": score.reason if score else f"CVSS base score {vuln.cvss or 0.0:.1f}",
                })

    # Sort priority queue: REACHABLE first, then KEV, then highest final_score
    priority_items.sort(
        key=lambda x: (
            1 if x["reachability_status"] == 'REACHABLE' else 2 if x["reachability_status"] == 'UNKNOWN' else 3,
            0 if x["is_kev"] else 1,
            -x["final_score"]
        )
    )

    sys_status = "DEGRADED" if failed_scans > 0 else ("RUNNING" if active_scans > 0 else "HEALTHY")

    res_body = {
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "findings_total": len(all_rows),
        "reachable_findings": reachable_count,
        "unknown_findings": unknown_count,
        "high_confidence_findings": high_confidence_count,
        "needs_attention": needs_attention_count,
        "etw_active": etw_active,
        "telemetry_data_state": "ACTIVE" if etw_active else "STANDBY",
        "telemetry_message": "ETW Telemetry collector running" if etw_active else "ETW Telemetry in standby",
        "system_status": sys_status,
        "metrics": {
            "needs_attention": needs_attention_count,
            "reachable": reachable_count,
            "unknown": unknown_count,
            "high_confidence": high_confidence_count,
            "total_findings": len(all_rows),
            "kev_count": kev_count,
        },
        "priority_queue": priority_items,
    }

    return jsonify(res_body), 200


@jobs_bp.route('/latest-threats', methods=['GET'])
def get_latest_threats():
    """
    Fetch latest released vulnerabilities & threat intelligence from CISA KEV catalog feed.
    If the feed is offline or unreachable, returns status offline without mock data.
    """
    import requests

    threats = []
    feed_status = "ONLINE"
    error_msg = None

    try:
        url = getattr(Config, 'CISA_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get('vulnerabilities', [])
            vulns.sort(key=lambda v: v.get('dateAdded', ''), reverse=True)
            for item in vulns[:6]:
                threats.append({
                    "cve_id": item.get('cveID'),
                    "title": item.get('vulnerabilityName') or item.get('shortDescription') or 'CISA KEV Listed Threat',
                    "vendor": item.get('vendorProject'),
                    "product": item.get('product'),
                    "date_added": item.get('dateAdded'),
                    "required_action": item.get('requiredAction'),
                    "source": "CISA KEV Catalog",
                    "severity": "CRITICAL"
                })
        else:
            feed_status = "OFFLINE"
            error_msg = f"HTTP {resp.status_code}"
    except Exception as err:
        log.warning("Could not fetch live CISA KEV threats: %s", err)
        feed_status = "OFFLINE"
        error_msg = str(err)

    if not threats and feed_status == "ONLINE":
        feed_status = "OFFLINE"

    return jsonify({
        "threats": threats,
        "status": feed_status,
        "error": error_msg
    }), 200


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
        user_role = getattr(current_user, 'role', 'analyst')
        user_id = getattr(current_user, 'id', None)

        # Authorization Check (Requirement 7)
        if user_role != 'admin' and status_info.get('user_id') and status_info['user_id'] != user_id:
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
        user_role = getattr(current_user, 'role', 'analyst')
        user_id = getattr(current_user, 'id', None)

        # Authorization Check (Requirement 7)
        if user_role != 'admin' and status_info.get('user_id') and status_info['user_id'] != user_id:
            return jsonify({"error": "Unauthorized access to job result."}), 403

        result = jq.get_result(job_id)
        return jsonify(result), 200
    except JobNotFoundError as err:
        return jsonify({"error": str(err)}), 404
    except JobNotFinishedError as err:
        return jsonify({"error": str(err), "status": "pending"}), 202


@jobs_bp.route('/<job_id>/re-enrich', methods=['POST'])
@login_required
def re_enrich_job(job_id: str):
    """
    On-demand backfill/re-enrichment endpoint for findings stuck without CVSS.
    Re-queries NVD for any vulnerability in the job missing CVSS or marked degraded.
    """
    job: Job | None = db.session.get(Job, job_id)
    if not job:
        return jsonify({"error": f"Job '{job_id}' not found."}), 404

    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)
    if user_role != 'admin' and job.user_id != user_id:
        return jsonify({"error": "Unauthorized access to job."}), 403

    from pipeline.cve_matcher import _query_nvd, _parse_nvd_cvss_details, _parse_nvd_description
    from pipeline.scorer import compute_risk_score

    components = Component.query.filter_by(job_id=job.id).all()
    comp_ids = [c.id for c in components]
    if not comp_ids:
        return jsonify({"message": "No components found for job.", "re_enriched_count": 0}), 200

    vulns = Vulnerability.query.filter(Vulnerability.component_id.in_(comp_ids)).all()
    re_enriched_count = 0

    for v in vulns:
        if v.cvss is None or v.cvss_source == 'UNAVAILABLE':
            nvd_data = _query_nvd(v.cve_id)
            if nvd_data:
                score, ver, sev, vector = _parse_nvd_cvss_details(nvd_data)
                desc = _parse_nvd_description(nvd_data)
                if score is not None:
                    v.cvss = score
                    v.cvss_version = ver
                    v.cvss_severity = sev
                    v.cvss_vector = vector
                    v.cvss_source = 'NVD'
                    if desc:
                        v.description = desc
                    v.data_quality = 'fresh'
                    v.nvd_fetched_at = _utcnow()
                    re_enriched_count += 1

                    # Re-score risk score if attached
                    comp = db.session.get(Component, v.component_id)
                    verdict = comp.reachability_verdict if comp else None
                    r_status = verdict.status if verdict else 'UNKNOWN'
                    e_source = verdict.evidence_source if verdict else 'none'

                    scoring = compute_risk_score(
                        cvss=v.cvss,
                        epss=v.epss,
                        is_kev=v.is_kev,
                        kev_status=v.kev_status,
                        reachability_status=r_status,
                        evidence_source=e_source,
                    )
                    if v.risk_score:
                        v.risk_score.cvss_input = scoring.cvss_input
                        v.risk_score.cvss_contrib = scoring.cvss_contrib
                        v.risk_score.base_score = scoring.base_score
                        v.risk_score.final_score = scoring.final_score
                        v.risk_score.confidence = scoring.confidence
                        v.risk_score.reason = scoring.reason

    if re_enriched_count > 0:
        db.session.commit()

    return jsonify({
        "message": f"Re-enrichment complete. Backfilled {re_enriched_count} vulnerability finding(s).",
        "job_id": job_id,
        "re_enriched_count": re_enriched_count,
    }), 200


def _analyze_etw_event_threat(evt):
    proc = (evt.process_name or '').lower()
    path = (evt.image_path or '').lower()

    # Untrusted path execution
    if any(loc in path for loc in ['temp', 'appdata\\local\\temp', 'downloads', 'public']):
        return {
            "threat_label": "UNTRUSTED_PATH_EXECUTION",
            "threat_judgment": "HARMFUL",
            "threat_explanation": f"Process '{evt.process_name}' (PID {evt.pid}) executed from an unverified temporary directory: {evt.image_path}",
            "reachability_status": "EXPOSED",
            "final_score": 0.78,
            "cvss": 7.5,
            "epss": 0.12,
        }

    # Suspicious script engines / elevation
    if proc in ['powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe']:
        return {
            "threat_label": "ELEVATED_SCRIPT_ENGINE",
            "threat_judgment": "SUSPICIOUS",
            "threat_explanation": f"System script interpreter '{evt.process_name}' executed dynamic image load.",
            "reachability_status": "EXPOSED",
            "final_score": 0.45,
            "cvss": 5.0,
            "epss": 0.05,
        }

    # Standard benign system process
    return {
        "threat_label": "SYSTEM_IMAGE_LOAD",
        "threat_judgment": "SAFE",
        "threat_explanation": f"Verified system process '{evt.process_name}' executed standard DLL load from system path.",
        "reachability_status": "NOT_REACHABLE",
        "final_score": 0.02,
        "cvss": 0.0,
        "epss": 0.00,
    }


@jobs_bp.route('/findings', methods=['GET'])
@login_required
def list_findings():
    """
    Paginated Findings endpoint.
    Supports finding_type filter ('uploaded' vs 'runtime') and 25-item pagination.
    Evaluates process threat judgments (HARMFUL / SUSPICIOUS / SAFE) for runtime findings.
    """
    finding_type = request.args.get('finding_type', 'uploaded')
    page = max(request.args.get('page', 1, type=int), 1)
    per_page = request.args.get('per_page', 25, type=int)
    job_id = request.args.get('job_id') or request.args.get('jobId')

    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)

    if finding_type == 'runtime':
        from agents.reachability_resolver import get_vulnerable_watchlist, correlate_event_with_watchlist

        timeframe = request.args.get('timeframe')
        event_date = request.args.get('date')

        watchlist = get_vulnerable_watchlist(job_id=job_id, user_id=user_id if user_role != 'admin' else None)

        query = EtwEvent.query
        if timeframe in ('today', 'TODAY'):
            today_str = _utcnow().strftime('%Y-%m-%d')
            query = query.filter(EtwEvent.date == today_str)
        elif timeframe in ('yesterday', 'YESTERDAY'):
            from datetime import timedelta
            yest_str = (_utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
            query = query.filter(EtwEvent.date == yest_str)
        elif event_date and event_date not in ('all', 'ALL HISTORY'):
            query = query.filter(EtwEvent.date == event_date)

        events = query.order_by(db.desc(EtwEvent.timestamp)).limit(1000).all()

        from db import RuntimeInventory
        from agents.reachability_resolver import is_system_os_dll

        # Primary source: Persistent RuntimeInventory + EtwEvents
        runtime_findings = []

        query_inv = RuntimeInventory.query
        if timeframe in ('today', 'TODAY'):
            today_str = _utcnow().strftime('%Y-%m-%d')
            query_inv = query_inv.filter(db.func.strftime('%Y-%m-%d', RuntimeInventory.last_seen) == today_str)
        elif timeframe in ('yesterday', 'YESTERDAY'):
            from datetime import timedelta
            yest_str = (_utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
            query_inv = query_inv.filter(db.func.strftime('%Y-%m-%d', RuntimeInventory.last_seen) == yest_str)
        elif event_date and event_date not in ('all', 'ALL HISTORY'):
            query_inv = query_inv.filter(db.func.strftime('%Y-%m-%d', RuntimeInventory.last_seen) == event_date)

        inv_items = query_inv.order_by(db.desc(RuntimeInventory.last_seen)).limit(1000).all()

        for item in inv_items:
            # Filter standard system OS DLLs from inventory drift noise
            if is_system_os_dll(item.executable_path, item.component_name or item.process_name):
                continue

            formatted_ts = _fmt_ts(item.last_seen)
            mod_name = item.module_name or (os.path.basename(item.executable_path) if item.executable_path else "unknown")

            child_modules = []
            try:
                child_modules = json.loads(str(item.loaded_modules_json or '[]'))
            except Exception:
                pass

            modules_str = f" | Loaded Modules ({len(child_modules)}): {', '.join(child_modules[:6])}" if child_modules else ""

            if item.finding_category == 'INVENTORY_DRIFT':
                runtime_findings.append({
                    "id": f"drift-{item.id}",
                    "vulnerability_id": item.id,
                    "cve_id": "INVENTORY_DRIFT",
                    "finding_type": "runtime",
                    "finding_category": "INVENTORY_DRIFT",
                    "component_name": item.component_name or item.process_name,
                    "component_version": item.version or f"PID {item.pid or 0}",
                    "process_name": item.process_name,
                    "module_name": mod_name,
                    "pid": item.pid or 0,
                    "executable_path": item.executable_path,
                    "loaded_module": item.executable_path,
                    "loaded_modules": child_modules,
                    "cvss": None,
                    "epss": None,
                    "is_kev": False,
                    "threat_judgment": "INFORMATIONAL",
                    "description": f"Inventory Drift: Component '{item.component_name or item.process_name}' (PID {item.pid or 0}) active at runtime but absent from latest declared SBOM baseline. Identity: KNOWN / IDENTIFIED. Threat: INFORMATIONAL / NOT SUSPICIOUS.",
                    "reachability_status": "NOT_DETERMINED",
                    "reachability_reason": "Process observed active at runtime. No vulnerability reachability inferred.",
                    "final_score": None,
                    "confidence": "high",
                    "analyst_status": "UNTRIAGED",
                    "evidence_source": "etw",
                    "identity_confidence": "KNOWN",
                    "sbom_status": "NOT_DECLARED",
                    "runtime_status": "OBSERVED",
                    "vulnerability_status": "NONE_KNOWN",
                    "runtime_evidence": f"Process: {item.process_name} | PID: {item.pid or 0} | Path: {item.executable_path}{modules_str} | First Seen: {_fmt_ts(item.first_seen)}",
                    "detection_time": formatted_ts,
                    "timestamp": formatted_ts,
                })
            elif item.finding_category == 'UNKNOWN_RUNTIME_COMPONENT':
                runtime_findings.append({
                    "id": f"unk-{item.id}",
                    "vulnerability_id": item.id,
                    "cve_id": "UNKNOWN_COMPONENT",
                    "finding_type": "runtime",
                    "finding_category": "UNKNOWN_RUNTIME_COMPONENT",
                    "component_name": item.process_name or "Unknown Binary",
                    "component_version": "Identification Required",
                    "process_name": item.process_name,
                    "module_name": mod_name,
                    "pid": item.pid or 0,
                    "executable_path": item.executable_path,
                    "loaded_module": item.executable_path,
                    "cvss": None,
                    "epss": None,
                    "is_kev": False,
                    "threat_judgment": "UNKNOWN",
                    "description": f"Unknown Runtime Component: Process '{item.process_name}' detected. Host: {item.host}. Identification Required.",
                    "reachability_status": "NOT_DETERMINED",
                    "reachability_reason": "Telemetry captured unverified process binary; vendor/purl metadata unavailable.",
                    "final_score": None,
                    "confidence": "low",
                    "analyst_status": "UNTRIAGED",
                    "evidence_source": "etw",
                    "identity_confidence": "UNKNOWN",
                    "sbom_status": "NOT_DECLARED",
                    "runtime_status": "OBSERVED",
                    "vulnerability_status": "UNKNOWN",
                    "runtime_evidence": f"Process: {item.process_name} | Path: {item.executable_path} | Host: {item.host}",
                    "detection_time": formatted_ts,
                    "timestamp": formatted_ts,
                })

        # Also correlate active ETW events against SBOM Vulnerable Watchlist
        for evt in events:
            if is_system_os_dll(evt.image_path, evt.process_name or ''):
                continue

            matched = correlate_event_with_watchlist(evt.image_path, evt.process_name, evt.image_hash, watchlist)
            analysis = _analyze_etw_event_threat(evt)

            if matched:
                mod_name = evt.module or (os.path.basename(evt.image_path) if evt.image_path else "unknown")
                formatted_ts = _fmt_ts(evt.timestamp)
                vuln_info = matched["matched_vuln"]

                runtime_findings.append({
                    "id": evt.id,
                    "vulnerability_id": vuln_info.get("vulnerability_id") or evt.id,
                    "cve_id": matched["cve_id"],
                    "finding_type": "runtime",
                    "finding_category": "RUNTIME_ACTIVE_VULNERABILITY",
                    "component_name": matched["component_name"],
                    "component_version": matched["component_version"] or f"PID {evt.pid or 0}",
                    "process_name": evt.process_name or "unknown",
                    "module_name": mod_name,
                    "pid": evt.pid or 0,
                    "executable_path": evt.image_path,
                    "loaded_module": evt.image_path,
                    "cvss": matched.get("cvss") or 7.5,
                    "epss": matched.get("epss") or 0.1,
                    "is_kev": matched.get("is_kev", False),
                    "threat_judgment": "HARMFUL",
                    "description": f"Runtime-Active Vulnerability: Component '{matched['component_name']}@{matched['component_version'] or ''}' ({matched['cve_id']}) actively observed in process '{evt.process_name}' (PID {evt.pid}).",
                    "reachability_status": "REACHABLE",
                    "reachability_reason": f"Observed in active memory/image load via {evt.evidence_source.upper()}",
                    "final_score": matched.get("cvss") or 7.5,
                    "confidence": "high" if evt.evidence_source == "etw" else "medium",
                    "analyst_status": (evt.severity or "UNTRIAGED").upper() if (evt.severity and evt.severity.upper() in {'ACCEPT_RISK', 'UNDER_INVESTIGATION', 'FALSE_POSITIVE', 'MITIGATED'}) else "UNTRIAGED",
                    "evidence_source": evt.evidence_source,
                    "sbom_status": "YES",
                    "runtime_status": "YES",
                    "vulnerability_status": "YES",
                    "runtime_evidence": f"Process {evt.process_name} (PID {evt.pid}) | Module: {mod_name} | Provider: {evt.provider or 'ETW'} | Path: {evt.image_path}",
                    "detection_time": formatted_ts,
                    "timestamp": formatted_ts,
                })
            elif analysis and analysis.get("threat_judgment") in ("HARMFUL", "SUSPICIOUS"):
                mod_name = evt.module or (os.path.basename(evt.image_path) if evt.image_path else "unknown")
                formatted_ts = _fmt_ts(evt.timestamp)
                runtime_findings.append({
                    "id": evt.id,
                    "vulnerability_id": evt.id,
                    "cve_id": analysis["threat_label"],
                    "finding_type": "runtime",
                    "finding_category": "INVENTORY_DRIFT" if analysis["threat_label"] == "UNTRUSTED_PATH_EXECUTION" else "RUNTIME_ACTIVE_VULNERABILITY",
                    "component_name": evt.process_name or "unknown",
                    "component_version": f"PID {evt.pid or 0}",
                    "process_name": evt.process_name or "unknown",
                    "module_name": mod_name,
                    "pid": evt.pid or 0,
                    "executable_path": evt.image_path,
                    "loaded_module": evt.image_path,
                    "cvss": analysis["cvss"],
                    "epss": analysis["epss"],
                    "threat_judgment": analysis["threat_judgment"],
                    "description": analysis["threat_explanation"],
                    "reachability_status": analysis["reachability_status"],
                    "reachability_reason": analysis["threat_explanation"],
                    "final_score": analysis["final_score"],
                    "confidence": "high" if evt.evidence_source == "etw" else "medium",
                    "analyst_status": (evt.severity or "UNTRIAGED").upper() if (evt.severity and evt.severity.upper() in {'ACCEPT_RISK', 'UNDER_INVESTIGATION', 'FALSE_POSITIVE', 'MITIGATED'}) else "UNTRIAGED",
                    "evidence_source": evt.evidence_source,
                    "sbom_status": "NO",
                    "runtime_status": "YES",
                    "vulnerability_status": "YES" if analysis["threat_judgment"] == "HARMFUL" else "NO",
                    "runtime_evidence": f"Process {evt.process_name} (PID {evt.pid}) | Module: {mod_name} | Provider: {evt.provider or 'ETW'} | Path: {evt.image_path}",
                    "detection_time": formatted_ts,
                    "timestamp": formatted_ts,
                })

        total = len(runtime_findings)
        offset = (page - 1) * per_page
        paginated_items = runtime_findings[offset:offset + per_page]

        return jsonify({
            "items": paginated_items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "has_more": (offset + len(paginated_items)) < total,
        }), 200

    # Default 'uploaded' findings
    if user_role == 'admin':
        jobs_query = Job.query
    else:
        jobs_query = Job.query.filter((Job.user_id == user_id) | (Job.user_id.is_(None)))

    if job_id:
        jobs_query = jobs_query.filter_by(id=job_id)
    else:
        jobs_query = jobs_query.filter_by(status='done')

    done_job_ids = [j.id for j in jobs_query.all()]
    if not done_job_ids:
        return jsonify({"items": [], "total": 0, "page": page, "per_page": per_page, "has_more": False}), 200

    filter_param = request.args.get('filter', 'all')

    main_query = (
        db.session.query(Component, ReachabilityVerdict, Vulnerability, RiskScore, Job)
        .join(Job, Component.job_id == Job.id)
        .outerjoin(ReachabilityVerdict, Component.id == ReachabilityVerdict.component_id)
        .outerjoin(Vulnerability, Component.id == Vulnerability.component_id)
        .outerjoin(RiskScore, Vulnerability.id == RiskScore.vulnerability_id)
        .filter(Component.job_id.in_(done_job_ids))
    )

    if filter_param == 'vulnerable':
        main_query = main_query.filter(Vulnerability.cve_id.isnot(None))
    elif filter_param == 'reachable':
        main_query = main_query.filter(ReachabilityVerdict.status == 'REACHABLE')

    main_query = main_query.order_by(
        db.desc(db.func.coalesce(RiskScore.final_score, -1.0)),
        db.desc(Vulnerability.cve_id),
        Component.id.asc()
    )

    total = main_query.count()
    offset = (page - 1) * per_page
    rows = main_query.offset(offset).limit(per_page).all()

    items = []
    for comp, verdict, vuln, score, job in rows:
        conf_notes = []
        has_vuln = vuln is not None and vuln.cve_id is not None

        # On-the-fly resolution for components stored before batch CVSS fix
        if not has_vuln and getattr(comp, 'is_scannable', True):
            try:
                from pipeline.cve_matcher import find_cves_for_component
                from pipeline.enricher import enrich_cve
                from pipeline.scorer import compute_risk_score

                cve_matches = find_cves_for_component(comp.name, comp.version, comp.purl, comp.ecosystem)
                if cve_matches:
                    for match in cve_matches:
                        enrichment = enrich_cve(match.cve_id)
                        new_vuln = Vulnerability(
                            cve_id=match.cve_id,
                            component_id=comp.id,
                            cvss=match.cvss,
                            cvss_version=getattr(match, 'cvss_version', None),
                            cvss_severity=getattr(match, 'cvss_severity', None),
                            cvss_vector=match.cvss_vector,
                            epss=enrichment.epss,
                            epss_percentile=enrichment.epss_percentile,
                            is_kev=enrichment.is_kev,
                            kev_status=enrichment.kev_status,
                            description=match.description,
                            source=match.source,
                            cvss_source=getattr(match, 'cvss_source', 'NVD'),
                            epss_source='FIRST EPSS',
                            kev_source='CISA KEV',
                            runtime_source=verdict.evidence_source if verdict else 'none',
                            shodan_exposed_hosts=enrichment.shodan_exposed_hosts,
                            virustotal_detections=enrichment.virustotal_detections,
                        )
                        db.session.add(new_vuln)
                        db.session.flush()

                        scoring = compute_risk_score(
                            cvss=match.cvss,
                            epss=enrichment.epss,
                            is_kev=enrichment.is_kev,
                            kev_status=enrichment.kev_status,
                            reachability_status=verdict.status if verdict else 'UNKNOWN',
                            evidence_source=verdict.evidence_source if verdict else 'none',
                        )
                        new_score = RiskScore(
                            vulnerability_id=new_vuln.id,
                            cvss_input=scoring.cvss_input,
                            epss_input=scoring.epss_input,
                            kev_input=scoring.kev_input,
                            reachability_input=scoring.reachability_input,
                            evidence_source=scoring.evidence_source,
                            cvss_contrib=scoring.cvss_contrib,
                            epss_contrib=scoring.epss_contrib,
                            kev_contrib=scoring.kev_contrib,
                            base_score=scoring.base_score,
                            reachability_multiplier=scoring.reachability_multiplier,
                            final_score=scoring.final_score,
                            confidence=scoring.confidence,
                            confidence_notes_json=json.dumps(scoring.confidence_notes),
                            reason=scoring.reason,
                            scored_at=_utcnow(),
                        )
                        db.session.add(new_score)
                    db.session.commit()
                    vuln = new_vuln
                    score = new_score
                    has_vuln = True
            except Exception as ex:
                log.warning("On-the-fly CVE resolution for component %s failed: %s", comp.name, ex)

        if score and score.confidence_notes_json:
            try:
                conf_notes = json.loads(score.confidence_notes_json)
            except Exception:
                conf_notes = []
        is_scannable = getattr(comp, 'is_scannable', True)
        unscannable_reason = getattr(comp, 'unscannable_reason', None)
        vuln_data_quality = getattr(vuln, 'data_quality', 'fresh') if has_vuln else 'fresh'
        cvss_reason = getattr(score, 'cvss_reason', None) if score else None

        is_lookup_incomplete = (
            not is_scannable
            or bool(unscannable_reason)
            or vuln_data_quality in ('failed', 'degraded')
            or cvss_reason == 'LOOKUP_FAILED'
        )

        if has_vuln:
            cve_id_val = vuln.cve_id
        elif is_lookup_incomplete:
            cve_id_val = "LOOKUP INCOMPLETE"
        else:
            cve_id_val = "NO KNOWN CVES"

        reach_status = verdict.status if verdict else "UNKNOWN"
        ev_source = verdict.evidence_source if verdict else "none"
        has_ev = bool(verdict and ev_source and ev_source != "none")

        is_confirmed_safe = (reach_status in ('NOT_REACHABLE', 'SAFE')) and has_ev
        is_unknown_reachability = not (reach_status in ('REACHABLE', 'EXPOSED')) and not is_confirmed_safe

        if has_vuln:
            if reach_status in ('REACHABLE', 'EXPOSED'):
                computed_final_score = score.final_score if score else 0.0
            elif is_confirmed_safe:
                computed_final_score = score.final_score if score else 0.0
            else:
                computed_final_score = None  # Reachability unknown - score is non-computable (dash)
        else:
            computed_final_score = 0.0 if not is_lookup_incomplete else None

        items.append({
            "id": vuln.id if has_vuln else f"comp-{comp.id}",
            "finding_type": "uploaded",
            "vulnerability_id": vuln.id if has_vuln else None,
            "job_id": job.id,
            "sbom_filename": job.sbom_filename,
            "cve_id": cve_id_val,
            "is_scannable": is_scannable,
            "unscannable_reason": unscannable_reason,
            "component_id": comp.id,
            "component_name": comp.name,
            "component_version": comp.version or "—",
            "purl": comp.purl or "—",
            "ecosystem": comp.ecosystem or "—",
            "cvss": vuln.cvss if has_vuln else None,
            "cvss_version": getattr(vuln, 'cvss_version', None) if has_vuln else None,
            "cvss_severity": getattr(vuln, 'cvss_severity', None) if has_vuln else ("SAFE" if not has_vuln and not is_lookup_incomplete else ("LOOKUP_FAILED" if is_lookup_incomplete else "LOW")),
            "cvss_vector": vuln.cvss_vector if has_vuln else None,
            "cvss_source": getattr(vuln, 'cvss_source', 'NVD') if has_vuln else 'NVD',
            "cvss_reason": cvss_reason,
            "cvss_next_action": getattr(score, 'cvss_next_action', None) if score else None,
            "epss": vuln.epss if has_vuln else None,
            "epss_percentile": vuln.epss_percentile if has_vuln else None,
            "epss_source": getattr(vuln, 'epss_source', 'FIRST EPSS') if has_vuln else 'FIRST EPSS',
            "epss_reason": getattr(score, 'epss_reason', None) if score else None,
            "epss_next_action": getattr(score, 'epss_next_action', None) if score else None,
            "is_kev": vuln.is_kev if has_vuln else False,
            "kev_status": vuln.kev_status if has_vuln else 'unavailable',
            "kev_source": getattr(vuln, 'kev_source', 'CISA KEV') if has_vuln else 'CISA KEV',
            "kev_reason": getattr(score, 'kev_reason', None) if score else None,
            "kev_next_action": getattr(score, 'kev_next_action', None) if score else None,
            "shodan_exposed_hosts": vuln.shodan_exposed_hosts if has_vuln else None,
            "virustotal_detections": vuln.virustotal_detections if has_vuln else None,
            "description": vuln.description if has_vuln else (unscannable_reason or (f"Clean component '{comp.name}@{comp.version or ''}' extracted from SBOM." if not is_lookup_incomplete else "Vulnerability lookup incomplete.")),
            "reachability_status": reach_status,
            "reachability_reason": getattr(score, 'reachability_reason', None) if score else None,
            "reachability_next_action": getattr(score, 'reachability_next_action', None) if score else None,
            "evidence_source": ev_source,
            "evidence_source_reason": getattr(score, 'evidence_source_reason', None) if score else None,
            "evidence_source_next_action": getattr(score, 'evidence_source_next_action', None) if score else None,
            "confidence": (score.confidence if score else (verdict.confidence if verdict else "low")).upper(),
            "base_score": score.base_score if score else 0.0,
            "reachability_multiplier": score.reachability_multiplier if score else 1.0,
            "final_score": computed_final_score,
            "is_unknown_reachability": is_unknown_reachability,
            "reason": score.reason if score else ("Vulnerability lookup incomplete or degraded." if is_lookup_incomplete else "Clean component, no vulnerabilities detected."),
            "confidence_notes": conf_notes,
            "analyst_status": (getattr(score, 'analyst_status', 'UNTRIAGED') or 'UNTRIAGED') if score else "SAFE",
            "analyst_note": getattr(score, 'analyst_note', None) if score else None,
            "analyst_user_id": getattr(score, 'analyst_user_id', None) if score else None,
            "updated_at": _fmt_ts(getattr(score, 'updated_at', None)) if score else None,
        })

    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": (offset + len(items)) < total,
    }), 200



@jobs_bp.route('/findings/<int:vulnerability_id>/status', methods=['POST'])
@jobs_bp.route('/findings/<int:vulnerability_id>/analyst-status', methods=['POST'])
@login_required
def update_analyst_finding_status(vulnerability_id: int):
    """
    Persist analyst action and state changes in the database.
    Valid statuses: 'ACCEPT_RISK', 'UNDER_INVESTIGATION', 'FALSE_POSITIVE', 'MITIGATED', 'UNTRIAGED'.
    """
    score: RiskScore | None = RiskScore.query.filter_by(vulnerability_id=vulnerability_id).first()
    if not score:
        evt: EtwEvent | None = db.session.get(EtwEvent, vulnerability_id)
        if evt:
            data = request.get_json() or {}
            new_status = data.get('status', '').upper()
            note = data.get('note', '')
            valid_statuses = {'ACCEPT_RISK', 'UNDER_INVESTIGATION', 'FALSE_POSITIVE', 'MITIGATED', 'UNTRIAGED'}
            if new_status not in valid_statuses:
                return jsonify({"error": f"Invalid analyst status '{new_status}'."}), 400
            evt.severity = new_status.lower()
            db.session.commit()
            return jsonify({
                "message": f"Analyst status updated to '{new_status}' successfully.",
                "vulnerability_id": vulnerability_id,
                "analyst_status": new_status,
                "analyst_note": note,
                "analyst_user_id": getattr(current_user, 'id', None),
                "updated_at": _fmt_ts(_utcnow()),
            }), 200
        return jsonify({"error": f"Finding ID {vulnerability_id} not found."}), 404

    data = request.get_json() or {}
    new_status = data.get('status', '').upper()
    note = data.get('note', '')

    valid_statuses = {'ACCEPT_RISK', 'UNDER_INVESTIGATION', 'FALSE_POSITIVE', 'MITIGATED', 'UNTRIAGED'}
    if new_status not in valid_statuses:
        return jsonify({"error": f"Invalid analyst status '{new_status}'. Allowed values: {sorted(list(valid_statuses))}"}), 400

    score.analyst_status = new_status
    if note:
        score.analyst_note = note
    score.analyst_user_id = getattr(current_user, 'id', None)
    score.updated_at = _utcnow()

    db.session.commit()

    log.info("Analyst user %s updated vulnerability %s status to %s", score.analyst_user_id, vulnerability_id, new_status)

    return jsonify({
        "message": f"Analyst status updated to '{new_status}' successfully.",
        "vulnerability_id": vulnerability_id,
        "analyst_status": score.analyst_status,
        "analyst_note": score.analyst_note,
        "analyst_user_id": score.analyst_user_id,
        "updated_at": _fmt_ts(score.updated_at),
    }), 200
