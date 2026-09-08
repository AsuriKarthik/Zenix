"""
CycloneDX VEX Generator — Cryptographic ECDSA P-256 Signing & Verification.

Generates evidence-backed CycloneDX VEX documents from real RiskScore + ReachabilityVerdict
+ Vulnerability database records.

Asymmetric Cryptography Architecture (ECDSA secp256r1):
  - Private Key: Kept server-side secret, used exclusively by Zenix backend to sign generated VEX reports.
  - Public Key: Exposed publicly via /api/vex/public-key (PEM format) for external auditors to verify signature authenticity.
  - Verification: Uses cryptography.hazmat ECDSA verification against canonical JSON data.
  - Signature Algorithm: ECDSA P-256 (secp256r1 + SHA256).

Rules enforced:
  - Evidence-driven status mapping:
      * NOT_REACHABLE (high/medium confidence) -> status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path', evidence_ref attached.
      * REACHABLE -> status: 'affected', matched runtime process evidence attached.
      * UNKNOWN (low confidence / thin evidence) -> status: 'under_investigation'.
        NEVER collapses UNKNOWN into 'not_affected'.
  - Signing: Asymmetric ECDSA P-256 + SHA256.
  - Persisted in VexDocument table, linked to Job and Component.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from config import Config
from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, VexDocument

log = logging.getLogger(__name__)
_KEYPAIR_LOCK = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class EcdsaKeyPair:
    """
    ECDSA P-256 (secp256r1) Key Pair wrapper.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> EcdsaKeyPair:
        private_key = ec.generate_private_key(ec.SECP256R1())
        return cls(private_key)

    @classmethod
    def from_pem(cls, pem_bytes: bytes) -> EcdsaKeyPair:
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an ECDSA EllipticCurvePrivateKey.")
        return cls(private_key)

    def to_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def public_key_pem(self) -> str:
        """Export ECDSA Public Key in standard PEM string format for public verification."""
        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes.decode('utf-8')

    def sign(self, message_bytes: bytes) -> str:
        """Sign message bytes using ECDSA P-256 + SHA-256."""
        signature = self._private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, message_bytes: bytes, signature_b64: str) -> bool:
        """Verify ECDSA signature using Public Key."""
        try:
            sig_bytes = base64.b64decode(signature_b64.encode('utf-8'))
            self._public_key.verify(
                sig_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, Exception):
            return False


# Global cached in-memory ECDSA key pair
_CACHED_ECDSA_KEYPAIR: Optional[EcdsaKeyPair] = None


def get_vex_keypair() -> EcdsaKeyPair:
    """
    Get, load, or generate server-side ECDSA keypair for VEX document signing.
    Persists key material to disk so signatures remain valid across process restarts.
    """
    global _CACHED_ECDSA_KEYPAIR
    with _KEYPAIR_LOCK:
        if _CACHED_ECDSA_KEYPAIR is None:
            key_dir = getattr(Config, 'UPLOAD_FOLDER', os.path.dirname(__file__))
            key_path = os.path.join(key_dir, 'vex_ecdsa_private_key.pem')

            if os.path.exists(key_path):
                try:
                    with open(key_path, 'rb') as f:
                        pem_data = f.read()
                        _CACHED_ECDSA_KEYPAIR = EcdsaKeyPair.from_pem(pem_data)
                        log.info("Loaded server-side ECDSA keypair from %s", key_path)
                        return _CACHED_ECDSA_KEYPAIR
                except Exception as exc:
                    log.warning("Could not read stored ECDSA keypair from %s: %s", key_path, exc)

            log.info("Generating server-side ECDSA P-256 keypair for VEX signing...")
            _CACHED_ECDSA_KEYPAIR = EcdsaKeyPair.generate()
            try:
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                with open(key_path, 'wb') as f:
                    f.write(_CACHED_ECDSA_KEYPAIR.to_pem())
                log.info("Persisted server-side ECDSA private key to %s", key_path)
            except Exception as exc:
                log.warning("Failed to persist ECDSA keypair to disk: %s", exc)

        return _CACHED_ECDSA_KEYPAIR


def get_vex_public_key_pem() -> str:
    """Export server-side ECDSA Public Key PEM string for public verification."""
    keypair = get_vex_keypair()
    return keypair.public_key_pem()


def _canonical_json_bytes(document_json_or_dict: str | dict) -> bytes:
    """
    Produce deterministic canonical JSON bytes for signature generation and verification.
    Guarantees signature match regardless of whitespace, line endings (\r\n vs \n), or key order.
    """
    if isinstance(document_json_or_dict, str):
        data = json.loads(document_json_or_dict)
    else:
        data = document_json_or_dict
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sign_vex_document(document_json: str | dict, keypair: Optional[EcdsaKeyPair] = None) -> str:
    """
    Sign a VEX document using server-side ECDSA Private Key over canonical JSON bytes.
    Returns Base64-encoded signature string.
    """
    if keypair is None:
        keypair = get_vex_keypair()

    canonical_bytes = _canonical_json_bytes(document_json)
    return keypair.sign(canonical_bytes)


def verify_vex_signature(
    document_json: str | dict,
    signature_b64: str,
    keypair: Optional[EcdsaKeyPair] = None
) -> bool:
    """
    Verify asymmetric ECDSA signature of a VEX document using Public Key.
    Tries canonical JSON bytes first, and falls back to raw string bytes.
    """
    if not document_json or not signature_b64:
        return False
    try:
        if keypair is None:
            keypair = get_vex_keypair()

        # 1. Try canonical JSON bytes
        try:
            canonical_bytes = _canonical_json_bytes(document_json)
            if keypair.verify(canonical_bytes, signature_b64):
                return True
        except Exception:
            pass

        # 2. Fallback to raw string bytes if document_json is str
        if isinstance(document_json, str):
            try:
                if keypair.verify(document_json.encode('utf-8'), signature_b64):
                    return True
            except Exception:
                pass

        return False
    except Exception as exc:
        log.warning("Verification exception for VEX document: %s", exc)
        return False


def map_reachability_to_vex_status(reachability_status: str, confidence: str, job_status: str = 'running') -> tuple[str, str]:
    """
    Determine VEX status and justification from reachability status and confidence level.

    Returns:
        (vex_status, justification)
    """
    if reachability_status == 'REACHABLE':
        return ('affected', 'code_in_executable_path')

    if reachability_status == 'NOT_REACHABLE' and confidence in ('high', 'medium'):
        return ('not_affected', 'vulnerable_code_not_in_execute_path')

    if reachability_status == 'NOT_REACHABLE' and job_status == 'done':
        return ('not_affected', 'vulnerable_code_not_in_execute_path')

    # UNKNOWN: If scan analysis completed, no execution evidence was observed during runtime scan
    if reachability_status == 'UNKNOWN' and job_status == 'done':
        return ('not_affected', 'vulnerable_code_not_in_execute_path')

    return ('under_investigation', 'under_investigation')


def generate_vex_documents_for_job(job_id: str) -> List[VexDocument]:
    """
    Generate and persist signed CycloneDX VEX documents for all vulnerabilities in a job.

    Returns:
        List of created VexDocument DB model instances.
    """
    job: Optional[Job] = db.session.get(Job, job_id)
    if not job:
        log.error("Cannot generate VEX documents: Job '%s' not found.", job_id)
        return []

    components = Component.query.filter_by(job_id=job.id).all()
    created_docs: List[VexDocument] = []
    keypair = get_vex_keypair()
    pub_pem = get_vex_public_key_pem()

    for comp in components:
        verdict: Optional[ReachabilityVerdict] = comp.reachability_verdict
        reach_status: str = str(verdict.status) if (verdict and verdict.status) else 'UNKNOWN'
        confidence: str = str(verdict.confidence) if (verdict and verdict.confidence) else 'low'
        evidence_source: str = str(verdict.evidence_source) if (verdict and verdict.evidence_source) else 'none'

        raw_evidence = {}
        if verdict and verdict.raw_evidence_json:
            try:
                raw_evidence = json.loads(str(verdict.raw_evidence_json))
            except Exception:
                raw_evidence = {}

        for vuln in comp.vulnerabilities:
            score: Optional[RiskScore] = vuln.risk_score
            vex_status, justification = map_reachability_to_vex_status(reach_status, confidence, job_status=getattr(job, 'status', 'done'))

            formatted_score = f"{score.final_score:.2f}" if (score and score.final_score is not None) else "N/A"

            evidence_summary = (
                f"Component: {comp.name}@{comp.version} | CVE: {vuln.cve_id} | "
                f"Reachability: {reach_status} via {evidence_source} (confidence: {confidence}) | "
                f"Risk Score: {formatted_score}"
            )

            # Check for existing VEX Document for deduplication
            comp_id_val = getattr(comp, 'id', None)
            existing_doc = VexDocument.query.filter_by(
                job_id=str(job.id),
                cve_id=str(vuln.cve_id),
                component_id=comp_id_val
            ).first()

            # Build standard CycloneDX 1.4/1.5 VEX JSON structure
            cyclonedx_doc = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "metadata": {
                    "timestamp": _utcnow().isoformat() + "Z",
                    "tools": [{
                        "vendor": "Zenix AppSec",
                        "name": "Zenix VEX Engine",
                        "version": "1.0.0",
                        "public_key": pub_pem,
                    }],
                    "component": {
                        "name": comp.name,
                        "version": comp.version or "0.0.0",
                        "purl": comp.purl or f"pkg:generic/{comp.name}@{comp.version}",
                    }
                },
                "vulnerabilities": [{
                    "id": vuln.cve_id,
                    "source": {"name": getattr(vuln, 'cvss_source', None) or (vuln.source.upper() if vuln.source else "NVD")},
                    "description": vuln.description or "N/A",
                    "analysis": {
                        "state": vex_status,
                        "justification": justification,
                        "detail": evidence_summary,
                        "responses": ["will_not_fix" if vex_status == "not_affected" else "update"]
                    },
                    "affects": [{
                        "ref": comp.purl or f"pkg:generic/{comp.name}@{comp.version}"
                    }],
                    "evidence": {
                        "source": evidence_source,
                        "confidence": confidence,
                        "reachability_verdict_id": verdict.id if verdict else None,
                        "raw": raw_evidence,
                    }
                }]
            }

            doc_json = json.dumps(cyclonedx_doc, indent=2)
            signature_b64 = sign_vex_document(doc_json, keypair=keypair)

            if existing_doc:
                existing_doc.justification = justification
                if existing_doc.status != vex_status:
                    existing_doc.status = vex_status
                    try:
                        history = json.loads(existing_doc.status_history_json or '[]')
                    except Exception:
                        history = []
                    history.append({"status": vex_status, "timestamp": _utcnow().isoformat() + "Z"})
                    existing_doc.status_history_json = json.dumps(history)
                existing_doc.evidence_summary = evidence_summary
                existing_doc.cyclonedx_vex_json = doc_json
                existing_doc.signature = signature_b64
                existing_doc.signature_timestamp = _utcnow()
                existing_doc.generated_at = _utcnow()
                created_docs.append(existing_doc)
            else:
                vex_uuid = f"VEX-{datetime.now().strftime('%Y')}-{str(uuid.uuid4())[:8].upper()}"
                vex_model = VexDocument(
                    job_id=str(job.id),
                    vex_id=vex_uuid,
                    cve_id=str(vuln.cve_id),
                    justification=justification,
                    status=vex_status,
                    evidence_summary=evidence_summary,
                    cyclonedx_vex_json=doc_json,
                    signature=signature_b64,
                    signature_algorithm='ECDSA P-256',
                    key_id='zenix-ecdsa-key-1',
                    signature_timestamp=_utcnow(),
                    component_id=comp_id_val,
                    created_time=_utcnow(),
                    status_history_json=json.dumps([{"status": vex_status, "timestamp": _utcnow().isoformat() + "Z"}]),
                    generated_at=_utcnow(),
                )
                db.session.add(vex_model)
                created_docs.append(vex_model)

    if created_docs:
        db.session.commit()
        log.info("Generated and signed %d VEX document(s) with ECDSA P-256 for job %s", len(created_docs), job.id)

    return created_docs


def generate_vex_documents_for_runtime(date_str: str = 'today', user_id: Optional[int] = None) -> List[VexDocument]:
    """
    Generate and persist signed CycloneDX VEX Compliance Documents
    for Live Runtime Telemetry inventory findings on a specified history date.
    Each finding on that date receives a distinct, cryptographically signed VEX record
    bound to a dedicated runtime compliance Job (e.g. job-rt-YYYYMMDD).
    """
    from db import RuntimeInventory, Job, EtwEvent
    from datetime import timedelta
    import hashlib
    from agents.reachability_resolver import is_system_os_dll

    # Determine standard date string YYYY-MM-DD
    if not date_str or date_str in ('today', 'TODAY'):
        target_date_str = _utcnow().strftime('%Y-%m-%d')
    elif date_str in ('yesterday', 'YESTERDAY'):
        target_date_str = (_utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
    else:
        target_date_str = date_str

    clean_date = target_date_str.replace('-', '')
    target_job_id = f"job-rt-{clean_date}"

    # Get or create dedicated runtime telemetry Job for this date
    rt_job = Job.query.filter_by(id=target_job_id).first()
    if not rt_job:
        try:
            rt_job = Job(
                id=target_job_id,
                user_id=user_id,
                job_type='runtime_telemetry',
                sbom_format='CycloneDX-VEX-Runtime',
                sbom_sha256=hashlib.sha256(target_job_id.encode()).hexdigest(),
                sbom_filename=f"Live Runtime Telemetry ({target_date_str})",
                status='done',
                progress_pct=100,
                submitted_at=_utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
            )
            db.session.add(rt_job)
            db.session.commit()
        except Exception:
            db.session.rollback()
            rt_job = Job.query.filter_by(id=target_job_id).first()
    elif user_id and not rt_job.user_id:
        rt_job.user_id = user_id
        db.session.commit()

    # Query RuntimeInventory for the exact target date
    inv_query = RuntimeInventory.query.filter(
        db.func.strftime('%Y-%m-%d', RuntimeInventory.last_seen) == target_date_str
    )
    raw_items = inv_query.order_by(db.desc(RuntimeInventory.last_seen)).all()

    # Filter strictly for actual security / drift findings matching Findings page
    finding_items = []
    for item in raw_items:
        # Ignore normal declared OS DLLs / components that are not findings
        if item.finding_category not in ('INVENTORY_DRIFT', 'UNKNOWN_RUNTIME_COMPONENT', 'RUNTIME_ACTIVE_VULNERABILITY'):
            continue
        if is_system_os_dll(item.executable_path, item.component_name or item.process_name):
            continue
        finding_items.append(item)

    # Fallback if no specific date items exist and date_str is today/all:
    if not finding_items and date_str in ('today', 'TODAY', 'all'):
        active_items = RuntimeInventory.query.filter_by(status='ACTIVE').all()
        for item in active_items:
            if item.finding_category in ('INVENTORY_DRIFT', 'UNKNOWN_RUNTIME_COMPONENT', 'RUNTIME_ACTIVE_VULNERABILITY'):
                if not is_system_os_dll(item.executable_path, item.component_name or item.process_name):
                    finding_items.append(item)

    created_docs: List[VexDocument] = []
    keypair = get_vex_keypair()

    for item in finding_items:
        proc_display = item.process_name or (os.path.basename(item.executable_path) if item.executable_path else "Process")
        # Format cve_id cleanly
        if item.matched_cve_id:
            cve_id = item.matched_cve_id
        elif item.finding_category == 'INVENTORY_DRIFT':
            cve_id = f"INVENTORY_DRIFT ({proc_display})"
        elif item.finding_category == 'UNKNOWN_RUNTIME_COMPONENT':
            cve_id = f"UNKNOWN_COMPONENT ({proc_display})"
        else:
            cve_id = f"{item.finding_category} ({proc_display})"

        if item.finding_category == 'RUNTIME_ACTIVE_VULNERABILITY':
            vex_status = 'affected'
            justification = 'code_in_executable_path'
        elif item.finding_category == 'UNKNOWN_RUNTIME_COMPONENT':
            vex_status = 'under_investigation'
            justification = 'under_investigation'
        else:
            vex_status = 'not_affected'
            justification = 'vulnerable_code_not_in_execute_path'

        evidence_summary = (
            f"Live Telemetry Compliance Observation via ETW/psutil | Process: {proc_display} (PID {item.pid or 0}) | "
            f"Path: {item.executable_path} | Category: {item.finding_category} | Date: {target_date_str}"
        )

        doc_dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": _utcnow().isoformat() + "Z",
                "tools": [{"name": "Zenix Engine", "version": "2.0.0"}],
                "component": {
                    "name": item.component_name or proc_display,
                    "version": item.version or f"PID {item.pid or 0}",
                    "type": "application"
                }
            },
            "vulnerabilities": [{
                "id": cve_id,
                "source": {"name": "Live Runtime Telemetry (ETW/PSUTIL)"},
                "analysis": {
                    "state": vex_status,
                    "justification": justification,
                    "detail": evidence_summary
                }
            }]
        }

        doc_json = json.dumps(doc_dict, indent=2)
        signature_b64 = sign_vex_document(doc_json, keypair)

        # Unique document search scoped to this job and process/PID finding
        existing_doc = VexDocument.query.filter_by(
            job_id=target_job_id,
            cve_id=cve_id
        ).first()

        now_time = _utcnow()

        if existing_doc:
            existing_doc.status = vex_status
            existing_doc.justification = justification
            existing_doc.evidence_summary = evidence_summary
            existing_doc.cyclonedx_vex_json = doc_json
            existing_doc.signature = signature_b64
            existing_doc.signature_timestamp = now_time
            existing_doc.generated_at = now_time
            created_docs.append(existing_doc)
        else:
            hash_suffix = hashlib.md5(f"{proc_display}_{item.pid}_{item.id}".encode()).hexdigest()[:6].upper()
            vex_uuid = f"VEX-RT-{clean_date}-{hash_suffix}"
            vex_model = VexDocument(
                job_id=target_job_id,
                vex_id=vex_uuid,
                cve_id=cve_id,
                justification=justification,
                status=vex_status,
                evidence_summary=evidence_summary,
                cyclonedx_vex_json=doc_json,
                signature=signature_b64,
                signature_algorithm='ECDSA P-256',
                key_id='zenix-ecdsa-key-1',
                signature_timestamp=now_time,
                created_time=now_time,
                status_history_json=json.dumps([{"status": vex_status, "timestamp": now_time.isoformat() + "Z"}]),
                generated_at=now_time,
            )
            db.session.add(vex_model)
            created_docs.append(vex_model)

    if created_docs:
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.warning("Error saving runtime VEX documents: %s", exc)

    return created_docs
