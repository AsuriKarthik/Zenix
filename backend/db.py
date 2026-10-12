"""
Database models — single source of truth for every entity Zenix stores.

All tables are defined here using SQLAlchemy 2.0 Mapped attributes + mapped_column.
init_db() is called once at app startup.
No global state, no in-memory dicts that survive only for one process lifetime.

Design rules enforced here:
  - Every risk score row stores the four inputs that produced it (never a bare number).
  - Every reachability verdict names its evidence_source ('etw' | 'psutil' | 'none').
  - Every vulnerability row tracks the freshness of each data source independently.
  - TelemetryAuditLog records every ETW activation/deactivation attempt (Requirement B3).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column

db: Any = SQLAlchemy()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model, UserMixin): # type: ignore[misc]
    __tablename__ = 'user'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    email: Mapped[str] = mapped_column(db.Text, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(db.Text, nullable=False)  # bcrypt
    role: Mapped[str] = mapped_column(db.Text, nullable=False, default='analyst')  # 'analyst' | 'admin'
    created_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    jobs = db.relationship('Job', back_populates='user', lazy='dynamic')
    telemetry_audit_logs = db.relationship('TelemetryAuditLog', back_populates='user', lazy='dynamic')

    def __init__(
        self,
        email: str,
        password_hash: str,
        role: str = 'analyst',
        created_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.created_at = created_at if created_at is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<User {self.email}>'


# ─────────────────────────────────────────────────────────────────────────────
# Jobs (one per SBOM upload)
# ─────────────────────────────────────────────────────────────────────────────

class Job(db.Model): # type: ignore[misc]
    __tablename__ = 'job'

    id: Mapped[str] = mapped_column(db.Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    sbom_format: Mapped[str] = mapped_column(db.Text, nullable=False)
    sbom_sha256: Mapped[str] = mapped_column(db.Text, nullable=False)
    sbom_filename: Mapped[Optional[str]] = mapped_column(db.Text)

    job_type: Mapped[str] = mapped_column(db.Text, nullable=False, default='sbom_analysis')
    status: Mapped[str] = mapped_column(db.Text, nullable=False, default='queued')
    error_msg: Mapped[Optional[str]] = mapped_column(db.Text)
    result_json: Mapped[Optional[str]] = mapped_column(db.Text)

    submitted_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    finished_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    updated_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    user = db.relationship('User', back_populates='jobs')
    components = db.relationship('Component', back_populates='job', lazy='dynamic')
    vex_documents = db.relationship('VexDocument', back_populates='job', lazy='dynamic')

    def __init__(
        self,
        sbom_format: str,
        sbom_sha256: str,
        id: Optional[str] = None,
        user_id: Optional[int] = None,
        sbom_filename: Optional[str] = None,
        job_type: str = 'sbom_analysis',
        status: str = 'queued',
        error_msg: Optional[str] = None,
        result_json: Optional[str] = None,
        submitted_at: Optional[datetime] = None,
        started_at: Optional[datetime] = None,
        finished_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ) -> None:
        super().__init__()
        self.id = id if id is not None else str(uuid.uuid4())
        self.user_id = user_id
        self.sbom_format = sbom_format
        self.sbom_sha256 = sbom_sha256
        self.sbom_filename = sbom_filename
        self.job_type = job_type
        self.status = status
        self.error_msg = error_msg
        self.result_json = result_json
        self.submitted_at = submitted_at if submitted_at is not None else _utcnow()
        self.started_at = started_at
        self.finished_at = finished_at
        self.updated_at = updated_at if updated_at is not None else _utcnow()

    @property
    def component_count(self) -> int:
        return self.components.count()

    @property
    def finding_count(self) -> int:
        return (
            db.session.query(RiskScore)
            .join(Vulnerability)
            .join(Component)
            .filter(Component.job_id == self.id)
            .count()
        )

    def __repr__(self) -> str:
        return f'<Job {self.id[:8]} status={self.status}>'


# ─────────────────────────────────────────────────────────────────────────────
# Components (parsed from SBOM)
# ─────────────────────────────────────────────────────────────────────────────

class Component(db.Model): # type: ignore[misc]
    __tablename__ = 'component'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(db.Text, db.ForeignKey('job.id'), nullable=False)

    name: Mapped[str] = mapped_column(db.Text, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(db.Text)
    purl: Mapped[Optional[str]] = mapped_column(db.Text)
    ecosystem: Mapped[Optional[str]] = mapped_column(db.Text)
    file_hash: Mapped[Optional[str]] = mapped_column(db.Text)

    job = db.relationship('Job', back_populates='components')
    vulnerabilities = db.relationship('Vulnerability', back_populates='component', lazy='dynamic')
    reachability_verdict = db.relationship(
        'ReachabilityVerdict', back_populates='component', uselist=False
    )

    def __init__(
        self,
        job_id: str,
        name: str,
        version: Optional[str] = None,
        purl: Optional[str] = None,
        ecosystem: Optional[str] = None,
        file_hash: Optional[str] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.job_id = job_id
        self.name = name
        self.version = version
        self.purl = purl
        self.ecosystem = ecosystem
        self.file_hash = file_hash
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<Component {self.name}@{self.version}>'


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerabilities (one row per component × CVE pair)
# ─────────────────────────────────────────────────────────────────────────────

class Vulnerability(db.Model): # type: ignore[misc]
    __tablename__ = 'vulnerability'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(db.Text, nullable=False)
    component_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('component.id'), nullable=False)

    cvss: Mapped[Optional[float]] = mapped_column(db.Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(db.Text)

    epss: Mapped[Optional[float]] = mapped_column(db.Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(db.Float)

    is_kev: Mapped[bool] = mapped_column(db.Boolean, nullable=False, default=False)
    kev_status: Mapped[str] = mapped_column(db.Text, nullable=False, default='unavailable')

    description: Mapped[Optional[str]] = mapped_column(db.Text)

    source: Mapped[str] = mapped_column(db.Text, nullable=False, default='osv')
    data_quality: Mapped[str] = mapped_column(db.Text, nullable=False, default='fresh')
    degradation_notes_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='[]')

    nvd_fetched_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    epss_fetched_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    kev_cached_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)

    component = db.relationship('Component', back_populates='vulnerabilities')
    risk_score = db.relationship('RiskScore', back_populates='vulnerability', uselist=False)

    def __init__(
        self,
        cve_id: str,
        component_id: int,
        cvss: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        epss: Optional[float] = None,
        epss_percentile: Optional[float] = None,
        is_kev: bool = False,
        kev_status: str = 'unavailable',
        description: Optional[str] = None,
        source: str = 'osv',
        data_quality: str = 'fresh',
        degradation_notes_json: str = '[]',
        nvd_fetched_at: Optional[datetime] = None,
        epss_fetched_at: Optional[datetime] = None,
        kev_cached_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.cve_id = cve_id
        self.component_id = component_id
        self.cvss = cvss
        self.cvss_vector = cvss_vector
        self.epss = epss
        self.epss_percentile = epss_percentile
        self.is_kev = is_kev
        self.kev_status = kev_status
        self.description = description
        self.source = source
        self.data_quality = data_quality
        self.degradation_notes_json = degradation_notes_json
        self.nvd_fetched_at = nvd_fetched_at
        self.epss_fetched_at = epss_fetched_at
        self.kev_cached_at = kev_cached_at
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<Vulnerability {self.cve_id} → component {self.component_id}>'


# ─────────────────────────────────────────────────────────────────────────────
# Reachability verdicts
# ─────────────────────────────────────────────────────────────────────────────

class ReachabilityVerdict(db.Model): # type: ignore[misc]
    __tablename__ = 'reachability_verdict'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    component_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('component.id'), nullable=False, unique=True)

    status: Mapped[str] = mapped_column(db.Text, nullable=False, default='UNKNOWN')
    confidence: Mapped[str] = mapped_column(db.Text, nullable=False, default='low')
    evidence_source: Mapped[str] = mapped_column(db.Text, nullable=False, default='none')
    matched_event_ids_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='[]')
    raw_evidence_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='{}')
    determined_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    component = db.relationship('Component', back_populates='reachability_verdict')

    def __init__(
        self,
        component_id: int,
        status: str = 'UNKNOWN',
        confidence: str = 'low',
        evidence_source: str = 'none',
        matched_event_ids_json: str = '[]',
        raw_evidence_json: str = '{}',
        determined_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.component_id = component_id
        self.status = status
        self.confidence = confidence
        self.evidence_source = evidence_source
        self.matched_event_ids_json = matched_event_ids_json
        self.raw_evidence_json = raw_evidence_json
        self.determined_at = determined_at if determined_at is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<ReachabilityVerdict component={self.component_id} {self.status}/{self.evidence_source}>'


# ─────────────────────────────────────────────────────────────────────────────
# ETW image-load events
# ─────────────────────────────────────────────────────────────────────────────

class EtwEvent(db.Model): # type: ignore[misc]
    __tablename__ = 'etw_event'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)
    pid: Mapped[Optional[int]] = mapped_column(db.Integer)
    process_name: Mapped[Optional[str]] = mapped_column(db.Text)
    image_path: Mapped[str] = mapped_column(db.Text, nullable=False)
    image_hash: Mapped[Optional[str]] = mapped_column(db.Text)
    evidence_source: Mapped[str] = mapped_column(db.Text, nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(db.Text, default='Microsoft-Windows-Kernel-Process')
    event_id: Mapped[Optional[int]] = mapped_column(db.Integer, default=2)

    def __init__(
        self,
        image_path: str,
        evidence_source: str,
        timestamp: Optional[datetime] = None,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        image_hash: Optional[str] = None,
        provider: str = 'Microsoft-Windows-Kernel-Process',
        event_id: int = 2,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.image_path = image_path
        self.evidence_source = evidence_source
        self.timestamp = timestamp if timestamp is not None else _utcnow()
        self.pid = pid
        self.process_name = process_name
        self.image_hash = image_hash
        self.provider = provider
        self.event_id = event_id
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<EtwEvent {self.process_name} {self.image_path}>'


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry Audit Logs (Part B — Requirement 3)
# ─────────────────────────────────────────────────────────────────────────────

class TelemetryAuditLog(db.Model): # type: ignore[misc]
    __tablename__ = 'telemetry_audit_log'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    user_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    action: Mapped[str] = mapped_column(db.Text, nullable=False)  # 'enable' | 'disable'
    result: Mapped[str] = mapped_column(db.Text, nullable=False)  # 'success' | 'auth_failed' | 'rate_limited' | 'elevation_failed'
    ip_address: Mapped[str] = mapped_column(db.Text, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(db.Text)

    user = db.relationship('User', back_populates='telemetry_audit_logs')

    def __init__(
        self,
        action: str,
        result: str,
        ip_address: str,
        user_id: Optional[int] = None,
        details: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.action = action
        self.result = result
        self.ip_address = ip_address
        self.user_id = user_id
        self.details = details
        self.timestamp = timestamp if timestamp is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<TelemetryAuditLog {self.action}:{self.result} by user={self.user_id} @ {self.ip_address}>'


# ─────────────────────────────────────────────────────────────────────────────
# Risk scores
# ─────────────────────────────────────────────────────────────────────────────

class RiskScore(db.Model): # type: ignore[misc]
    __tablename__ = 'risk_score'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        db.Integer, db.ForeignKey('vulnerability.id'), nullable=False, unique=True
    )

    cvss_input: Mapped[Optional[float]] = mapped_column(db.Float)
    epss_input: Mapped[Optional[float]] = mapped_column(db.Float)
    kev_input: Mapped[bool] = mapped_column(db.Boolean, nullable=False)
    reachability_input: Mapped[str] = mapped_column(db.Text, nullable=False)
    evidence_source: Mapped[str] = mapped_column(db.Text, nullable=False)

    cvss_contrib: Mapped[float] = mapped_column(db.Float, nullable=False)
    epss_contrib: Mapped[float] = mapped_column(db.Float, nullable=False)
    kev_contrib: Mapped[float] = mapped_column(db.Float, nullable=False)
    base_score: Mapped[float] = mapped_column(db.Float, nullable=False)
    reachability_multiplier: Mapped[float] = mapped_column(db.Float, nullable=False)
    final_score: Mapped[float] = mapped_column(db.Float, nullable=False)

    confidence: Mapped[str] = mapped_column(db.Text, nullable=False)
    confidence_notes_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='[]')
    reason: Mapped[str] = mapped_column(db.Text, nullable=False)

    scored_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    vulnerability = db.relationship('Vulnerability', back_populates='risk_score')

    def __init__(
        self,
        vulnerability_id: int,
        kev_input: bool,
        reachability_input: str,
        evidence_source: str,
        cvss_contrib: float,
        epss_contrib: float,
        kev_contrib: float,
        base_score: float,
        reachability_multiplier: float,
        final_score: float,
        confidence: str,
        reason: str,
        cvss_input: Optional[float] = None,
        epss_input: Optional[float] = None,
        confidence_notes_json: str = '[]',
        scored_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.vulnerability_id = vulnerability_id
        self.cvss_input = cvss_input
        self.epss_input = epss_input
        self.kev_input = kev_input
        self.reachability_input = reachability_input
        self.evidence_source = evidence_source
        self.cvss_contrib = cvss_contrib
        self.epss_contrib = epss_contrib
        self.kev_contrib = kev_contrib
        self.base_score = base_score
        self.reachability_multiplier = reachability_multiplier
        self.final_score = final_score
        self.confidence = confidence
        self.confidence_notes_json = confidence_notes_json
        self.reason = reason
        self.scored_at = scored_at if scored_at is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<RiskScore {self.final_score:.2f} {self.confidence} for vuln={self.vulnerability_id}>'


# ─────────────────────────────────────────────────────────────────────────────
# VEX documents (step 8)
# ─────────────────────────────────────────────────────────────────────────────

class VexDocument(db.Model): # type: ignore[misc]
    __tablename__ = 'vex_document'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(db.Text, db.ForeignKey('job.id'), nullable=False)
    component_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('component.id'))

    vex_id: Mapped[str] = mapped_column(db.Text, unique=True, nullable=False)
    cve_id: Mapped[str] = mapped_column(db.Text, nullable=False)
    justification: Mapped[str] = mapped_column(db.Text, nullable=False)
    status: Mapped[str] = mapped_column(db.Text, nullable=False)

    evidence_summary: Mapped[Optional[str]] = mapped_column(db.Text)
    cyclonedx_vex_json: Mapped[Optional[str]] = mapped_column(db.Text)
    signature: Mapped[Optional[str]] = mapped_column(db.Text)

    generated_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    job = db.relationship('Job', back_populates='vex_documents')

    def __init__(
        self,
        job_id: str,
        vex_id: str,
        cve_id: str,
        justification: str,
        status: str,
        component_id: Optional[int] = None,
        evidence_summary: Optional[str] = None,
        cyclonedx_vex_json: Optional[str] = None,
        signature: Optional[str] = None,
        generated_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.job_id = job_id
        self.vex_id = vex_id
        self.cve_id = cve_id
        self.justification = justification
        self.status = status
        self.component_id = component_id
        self.evidence_summary = evidence_summary
        self.cyclonedx_vex_json = cyclonedx_vex_json
        self.signature = signature
        self.generated_at = generated_at if generated_at is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<VexDocument {self.vex_id} {self.cve_id} {self.status}>'


# ─────────────────────────────────────────────────────────────────────────────
# Init helper
# ─────────────────────────────────────────────────────────────────────────────

def init_db(app: Any) -> None:
    """
    Bind SQLAlchemy to the Flask app and create all tables.
    Call once at application startup.
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()
