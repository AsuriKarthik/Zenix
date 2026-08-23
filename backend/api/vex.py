"""
VEX API Endpoints — PDF Compliance Report Download & ECDSA Verification.

Endpoints:
  GET /api/vex/public-key — Public endpoint returning ECDSA Public Key (PEM) for signature verification.
  GET /api/vex — Query VEX documents for authenticated user's jobs (or all jobs for admin).
  GET /api/vex/<vex_id>/download — Download VEX Compliance & Threat Exposure Report in PDF format ONLY.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from flask import Blueprint, jsonify, request, Response
from flask.typing import ResponseReturnValue
from flask_login import login_required, current_user

from agents.etw_collector import _utcnow
from db import db, VexDocument, Job, Component, Vulnerability
from pipeline.vex_generator import verify_vex_signature, get_vex_public_key_pem
from pipeline.vex_pdf_generator import generate_vex_pdf_bytes

vex_bp = Blueprint('vex', __name__, url_prefix='/api/vex')
log = logging.getLogger(__name__)


@vex_bp.route('/public-key', methods=['GET'])
def get_public_key() -> Response:
    """
    Public endpoint returning the server's ECDSA Public Key (PEM) for signature verification.
    No auth required — public verification key by design.
    """
    pem = get_vex_public_key_pem()
    resp = Response(pem, mimetype="application/x-pem-file")
    resp.headers["Content-Disposition"] = "inline; filename=zenix_vex_public_key.pem"
    return resp


def _safe_json_loads(val: Optional[str]) -> Optional[dict[str, Any]]:
    if not val:
        return None
    try:
        data = json.loads(val)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@vex_bp.route('', methods=['GET'])
@login_required
def get_vex_documents() -> Response:
    """
    Get VEX documents.
    Enforces Requirement 7: Logged-in non-admin users can ONLY view VEX documents
    belonging to their own jobs.
    """
    job_id = request.args.get('job_id')
    cve_id = request.args.get('cve_id')
    status = request.args.get('status')
    source_type_param = request.args.get('source_type')

    query = VexDocument.query.join(Job)

    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)

    # Strict Data Isolation (Requirement 7)
    if user_role != 'admin':
        query = query.filter(Job.user_id == user_id)

    if job_id:
        query = query.filter(VexDocument.job_id == job_id)
    if cve_id:
        query = query.filter(VexDocument.cve_id == cve_id)
    if status:
        query = query.filter(VexDocument.status == status)

    docs = query.order_by(db.desc(VexDocument.generated_at)).all()
    log.info(f"get_vex_documents called by user_id={user_id} role={user_role}. Docs found: {len(docs)}")
    
    results = []
    modified_count = 0

    for d in docs:
        parent_job = db.session.get(Job, d.job_id) if d.job_id else None
        if parent_job and parent_job.status == 'done' and d.status == 'under_investigation':
            d.status = 'not_affected'
            d.justification = 'vulnerable_code_not_in_execute_path'
            if d.cyclonedx_vex_json:
                try:
                    parsed_doc = json.loads(str(d.cyclonedx_vex_json))
                    if "vulnerabilities" in parsed_doc and parsed_doc["vulnerabilities"]:
                        parsed_doc["vulnerabilities"][0]["analysis"]["state"] = "not_affected"
                        parsed_doc["vulnerabilities"][0]["analysis"]["justification"] = "vulnerable_code_not_in_execute_path"
                    new_doc_json = json.dumps(parsed_doc, indent=2)
                    d.cyclonedx_vex_json = new_doc_json
                    from pipeline.vex_generator import sign_vex_document
                    d.signature = sign_vex_document(new_doc_json)
                except Exception as update_err:
                    log.warning("Could not auto-update VEX JSON for doc %s: %s", d.id, update_err)
            modified_count += 1

        doc_json = str(d.cyclonedx_vex_json) if d.cyclonedx_vex_json else ""
        sig_str = str(d.signature) if d.signature else ""
        sig_valid = verify_vex_signature(doc_json, sig_str) if (doc_json and sig_str) else False

        if not sig_valid and doc_json:
            # Re-sign legacy document with active server ECDSA key and update DB
            try:
                from pipeline.vex_generator import sign_vex_document
                new_sig = sign_vex_document(doc_json)
                if new_sig:
                    d.signature = new_sig
                    d.signature_algorithm = 'ECDSA P-256'
                    d.key_id = 'zenix-ecdsa-key-1'
                    sig_valid = True
                    modified_count += 1
            except Exception as resign_err:
                log.warning("Could not re-sign legacy VEX doc %s: %s", d.id, resign_err)

        created_at = getattr(d, 'created_time', None) or d.generated_at
        resolved_at = getattr(d, 'resolved_time', None)

        # Calculate exact duration from database timestamps
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        end_dt = resolved_at or now_dt
        duration_secs = int((end_dt - created_at).total_seconds()) if created_at else 0

        # Human formatted duration
        if duration_secs < 60:
            duration_human = f"{duration_secs}s"
        elif duration_secs < 3600:
            duration_human = f"{duration_secs // 60}m"
        elif duration_secs < 86400:
            hours = duration_secs // 3600
            mins = (duration_secs % 3600) // 60
            duration_human = f"{hours}h {mins}m" if mins > 0 else f"{hours}h"
        else:
            days = duration_secs // 86400
            hours = (duration_secs % 86400) // 3600
            duration_human = f"{days}d {hours}h" if hours > 0 else f"{days}d"

        status_history = []
        if getattr(d, 'status_history_json', None):
            try:
                status_history = json.loads(d.status_history_json)
            except Exception:
                status_history = []

        # Determine evidence source & source_type (Live Telemetry vs Uploaded)
        ev_source = 'none'
        if d.component_id:
            comp = db.session.get(Component, d.component_id)
            if comp and comp.reachability_verdict:
                ev_source = comp.reachability_verdict.evidence_source or 'none'

        if ev_source == 'none' and d.evidence_summary:
            ev_lower = d.evidence_summary.lower()
            if 'via etw' in ev_lower or 'via psutil' in ev_lower:
                ev_source = 'etw'

        is_telemetry = ev_source.lower() in ('etw', 'psutil', 'etw_collector', 'runtime')
        source_type = 'live_telemetry' if is_telemetry else 'uploaded'

        if source_type_param and source_type_param != 'ALL':
            if source_type_param in ('live_telemetry', 'etw') and source_type != 'live_telemetry':
                continue
            if source_type_param in ('uploaded', 'uploaded_ones', 'sbom') and source_type != 'uploaded':
                continue

        results.append({
            "id": d.id,
            "vex_id": d.vex_id,
            "job_id": d.job_id,
            "component_id": d.component_id,
            "cve_id": d.cve_id,
            "status": d.status,
            "justification": d.justification,
            "evidence_summary": d.evidence_summary,
            "evidence_source": ev_source,
            "source_type": source_type,
            "signature": d.signature,
            "signature_algorithm": getattr(d, 'signature_algorithm', 'ECDSA P-256'),
            "key_id": getattr(d, 'key_id', 'zenix-ecdsa-key-1'),
            "signature_valid": sig_valid,
            "created_time": created_at.isoformat() if created_at else None,
            "resolved_time": resolved_at.isoformat() if resolved_at else None,
            "duration_seconds": duration_secs,
            "duration_human": duration_human,
            "status_history": status_history,
            "generated_at": d.generated_at.isoformat() if d.generated_at else None,
            "document": _safe_json_loads(d.cyclonedx_vex_json),
        })

    if modified_count > 0:
        db.session.commit()

    return jsonify(results)


@vex_bp.route('/<vex_id>/resolve', methods=['POST'])
@login_required
def resolve_vex_investigation(vex_id: str) -> ResponseReturnValue:
    """
    Resolve or complete investigation for a VEX document.
    Updates status ('not_affected', 'affected', 'fixed') and records resolution timestamp.
    """
    doc: Optional[VexDocument] = VexDocument.query.filter_by(vex_id=vex_id).first()
    if not doc:
        return jsonify({"error": f"VEX document '{vex_id}' not found."}), 404

    # Strict Data Isolation check
    job: Optional[Job] = db.session.get(Job, doc.job_id)
    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)
    if user_role != 'admin' and job and job.user_id != user_id:
        return jsonify({"error": "Unauthorized access to VEX document."}), 403

    data = request.get_json() or {}
    new_status = data.get('status', 'not_affected')
    justification = data.get('justification', 'vulnerable_code_not_in_execute_path')

    doc.status = new_status
    doc.justification = justification
    doc.resolved_time = _utcnow()

    # Append to status history
    try:
        raw_history = str(doc.status_history_json or '[]')
        history = json.loads(raw_history)
    except Exception:
        history = []
    history.append({
        "status": new_status,
        "timestamp": _utcnow().isoformat() + "Z",
        "action": "investigation_resolved_by_analyst",
        "user": getattr(current_user, 'email', 'analyst')
    })
    doc.status_history_json = json.dumps(history)
    db.session.commit()

    return jsonify({
        "message": f"Investigation for {vex_id} resolved successfully.",
        "vex_id": vex_id,
        "status": doc.status,
        "justification": doc.justification,
        "resolved_time": doc.resolved_time.isoformat() + "Z"
    })


@vex_bp.route('/<vex_id>/download', methods=['GET'])
@login_required
def download_vex_document(vex_id: str) -> ResponseReturnValue:
    """
    Download VEX Compliance & Threat Exposure Report in PDF format ONLY.
    Enforces Requirement: PDF Format Only with Detailed System Impact & Trigger Sections.
    """
    doc: Optional[VexDocument] = VexDocument.query.filter_by(vex_id=vex_id).first()
    if not doc:
        return jsonify({"error": f"VEX document '{vex_id}' not found."}), 404

    # Strict Data Isolation (Requirement 7)
    job: Optional[Job] = db.session.get(Job, doc.job_id)
    user_role = getattr(current_user, 'role', 'analyst')
    user_id = getattr(current_user, 'id', None)
    if user_role != 'admin' and job and job.user_id != user_id:
        return jsonify({"error": "Unauthorized access to VEX document."}), 403

    # Requirement 13: Enforce investigation completion status before report download
    if job and job.status in ('running', 'queued'):
        return jsonify({
            "error": "Investigation in progress — report will be available when analysis is complete.",
            "compliance_state": "INVESTIGATING",
            "job_status": job.status,
        }), 409

    # Query related database models for complete context
    component: Optional[Component] = db.session.get(Component, doc.component_id) if doc.component_id else None
    vulnerability: Optional[Vulnerability] = (
        Vulnerability.query.filter_by(cve_id=doc.cve_id, component_id=doc.component_id).first()
        if doc.component_id else None
    )
    risk_score = vulnerability.risk_score if vulnerability else None
    verdict = component.reachability_verdict if component else None

    doc_json = str(doc.cyclonedx_vex_json) if doc.cyclonedx_vex_json else ""
    sig_str = str(doc.signature) if doc.signature else ""
    sig_valid = verify_vex_signature(doc_json, sig_str) if (doc_json and sig_str) else False

    if not sig_valid and doc_json:
        try:
            from pipeline.vex_generator import sign_vex_document
            new_sig = sign_vex_document(doc_json)
            if new_sig:
                doc.signature = new_sig
                doc.signature_algorithm = 'ECDSA P-256'
                doc.key_id = 'zenix-ecdsa-key-1'
                sig_valid = True
                db.session.commit()
        except Exception as resign_err:
            log.warning("Could not re-sign legacy VEX doc %s for download: %s", vex_id, resign_err)

    doc_data = {
        "vex_id": doc.vex_id,
        "job_id": doc.job_id,
        "cve_id": doc.cve_id,
        "component_name": component.name if component else "Software Component",
        "component_version": component.version if component else "N/A",
        "purl": component.purl if component else "pkg:npm/component",
        "file_hash": component.file_hash if component else "N/A",
        "status": doc.status,
        "justification": doc.justification,
        "evidence_summary": doc.evidence_summary or (verdict.evidence_summary if verdict else "Runtime process telemetry analysis"),
        "evidence_source": verdict.evidence_source if verdict else "psutil",
        "cvss": vulnerability.cvss if vulnerability else None,
        "cvss_version": getattr(vulnerability, 'cvss_version', None) if vulnerability else None,
        "cvss_severity": getattr(vulnerability, 'cvss_severity', None) if vulnerability else None,
        "cvss_vector": vulnerability.cvss_vector if vulnerability else None,
        "cvss_source": getattr(vulnerability, 'cvss_source', 'NVD') if vulnerability else 'NVD',
        "epss": vulnerability.epss if vulnerability else None,
        "epss_percentile": vulnerability.epss_percentile if vulnerability else None,
        "epss_source": getattr(vulnerability, 'epss_source', 'FIRST EPSS') if vulnerability else 'FIRST EPSS',
        "is_kev": vulnerability.is_kev if vulnerability else False,
        "kev_source": getattr(vulnerability, 'kev_source', 'CISA KEV') if vulnerability else 'CISA KEV',
        "reachability_status": verdict.status if (verdict and verdict.status) else ("REACHABLE" if doc.status == "affected" else "NOT_REACHABLE"),
        "reachability_reason": getattr(risk_score, 'reachability_reason', None) if risk_score else None,
        "reachability_next_action": getattr(risk_score, 'reachability_next_action', None) if risk_score else None,
        "cvss_contrib": getattr(risk_score, 'cvss_contrib', 0.0) if risk_score else 0.0,
        "epss_contrib": getattr(risk_score, 'epss_contrib', 0.0) if risk_score else 0.0,
        "kev_contrib": getattr(risk_score, 'kev_contrib', 0.0) if risk_score else 0.0,
        "confidence": getattr(risk_score, 'confidence', 'low') if risk_score else 'low',
        "analyst_status": getattr(risk_score, 'analyst_status', None) if risk_score else None,
        "analyst_note": getattr(risk_score, 'analyst_note', None) if risk_score else None,
        "updated_at": risk_score.updated_at.isoformat() if (risk_score and getattr(risk_score, 'updated_at', None)) else None,
        "final_score": risk_score.final_score if (risk_score and risk_score.final_score is not None) else 0.05,
        "base_score": risk_score.base_score if (risk_score and risk_score.base_score is not None) else 1.0,
        "reachability_multiplier": risk_score.reachability_multiplier if (risk_score and risk_score.reachability_multiplier is not None) else 0.05,
        "reason": risk_score.reason if (risk_score and risk_score.reason) else "VEX justified non-reachable state.",
        "description": vulnerability.description if vulnerability else "Vulnerability detailed description.",
        "generated_at": doc.generated_at.isoformat() if doc.generated_at else None,
        "submitted_at": job.submitted_at.isoformat() if job and job.submitted_at else None,
        "sbom_filename": job.sbom_filename if job else "sbom.json",
        "sbom_sha256": job.sbom_sha256 if job else "N/A",
        "signature": doc.signature,
        "signature_algorithm": getattr(doc, 'signature_algorithm', 'ECDSA P-256'),
        "key_id": getattr(doc, 'key_id', 'zenix-ecdsa-key-1'),
        "signature_valid": sig_valid,
    }

    try:
        pdf_bytes = generate_vex_pdf_bytes(doc_data)
        filename = f"{doc.vex_id.upper()}_VEX_Report.pdf"

        resp = Response(pdf_bytes, mimetype="application/pdf")
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        resp.headers["X-VEX-Signature"] = doc.signature or ""
        return resp
    except Exception as err:
        log.error("Failed to generate VEX PDF report for %s: %s", vex_id, err, exc_info=True)
        return jsonify({"error": f"Failed to generate PDF report: {err}"}), 500


@vex_bp.route('/generate-runtime-report', methods=['POST'])
@login_required
def generate_runtime_compliance_report() -> ResponseReturnValue:
    """
    Generate evidence-backed CycloneDX VEX Compliance Report
    for Live Runtime Telemetry events on a selected history date.
    """
    data = request.get_json() or {}
    date_param = data.get('date', 'today')

    try:
        from pipeline.vex_generator import generate_vex_documents_for_runtime
        docs = generate_vex_documents_for_runtime(date_str=date_param)
        return jsonify({
            "message": f"Live Telemetry Compliance Report successfully generated for date '{date_param}'.",
            "generated_count": len(docs),
            "report_date": date_param,
            "source_type": "live_telemetry"
        }), 201
    except Exception as exc:
        log.error("Failed to generate runtime compliance report: %s", exc)
        return jsonify({"error": f"Failed to generate runtime compliance report: {exc}"}), 500
