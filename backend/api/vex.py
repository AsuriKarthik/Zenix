"""
VEX API Endpoints — Requirement 3 (ECDSA Public Key) + Requirement 7 (Strict User Data Isolation).

Endpoints:
  GET /api/vex/public-key — Public endpoint returning ECDSA Public Key (PEM) for signature verification.
  GET /api/vex — Query VEX documents for authenticated user's jobs (or all jobs for admin).
  GET /api/vex/<vex_id>/download — Download raw signed CycloneDX VEX JSON document (ownership checked).
"""

from __future__ import annotations

import json
import logging
from flask import Blueprint, jsonify, request, Response
from flask_login import login_required, current_user

from db import db, VexDocument, Job
from pipeline.vex_generator import verify_vex_signature, get_vex_public_key_pem

vex_bp = Blueprint('vex', __name__, url_prefix='/api/vex')
log = logging.getLogger(__name__)


@vex_bp.route('/public-key', methods=['GET'])
def get_public_key():
    """
    Public endpoint returning the server's ECDSA Public Key (PEM) for signature verification.
    No auth required — public verification key by design.
    """
    pem = get_vex_public_key_pem()
    return Response(
        pem,
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": "inline; filename=zenix_vex_public_key.pem",
        }
    )


@vex_bp.route('', methods=['GET'])
@login_required
def get_vex_documents():
    """
    Get VEX documents.
    Enforces Requirement 7: Logged-in non-admin users can ONLY view VEX documents
    belonging to their own jobs.
    """
    job_id = request.args.get('job_id')
    cve_id = request.args.get('cve_id')
    status = request.args.get('status')

    query = VexDocument.query.join(Job)

    # Strict Data Isolation (Requirement 7)
    if current_user.role != 'admin':
        query = query.filter(Job.user_id == current_user.id)

    if job_id:
        query = query.filter(VexDocument.job_id == job_id)
    if cve_id:
        query = query.filter(VexDocument.cve_id == cve_id)
    if status:
        query = query.filter(VexDocument.status == status)

    docs = query.order_by(db.desc(VexDocument.generated_at)).all()
    results = []

    for d in docs:
        sig_valid = verify_vex_signature(d.cyclonedx_vex_json, d.signature) if (d.cyclonedx_vex_json and d.signature) else False
        results.append({
            "id": d.id,
            "vex_id": d.vex_id,
            "job_id": d.job_id,
            "component_id": d.component_id,
            "cve_id": d.cve_id,
            "status": d.status,
            "justification": d.justification,
            "evidence_summary": d.evidence_summary,
            "signature": d.signature,
            "signature_valid": sig_valid,
            "generated_at": d.generated_at.isoformat() if d.generated_at else None,
            "document": json.loads(d.cyclonedx_vex_json) if d.cyclonedx_vex_json else None,
        })

    return jsonify(results), 200


@vex_bp.route('/<vex_id>/download', methods=['GET'])
@login_required
def download_vex_document(vex_id: str):
    """
    Download raw CycloneDX VEX JSON document by vex_id.
    Enforces Requirement 7: Non-admin users can only download VEX documents for their own jobs.
    """
    doc: VexDocument | None = VexDocument.query.filter_by(vex_id=vex_id).first()
    if not doc or not doc.cyclonedx_vex_json:
        return jsonify({"error": f"VEX document '{vex_id}' not found."}), 404

    # Strict Data Isolation (Requirement 7)
    job: Job | None = db.session.get(Job, doc.job_id)
    if current_user.role != 'admin' and job and job.user_id != current_user.id:
        return jsonify({"error": "Unauthorized access to VEX document."}), 403

    filename = f"{doc.vex_id.lower()}.cdx.json"
    return Response(
        doc.cyclonedx_vex_json,
        mimetype="application/vnd.cyclonedx+json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "X-VEX-Signature": doc.signature or "",
        }
    )
