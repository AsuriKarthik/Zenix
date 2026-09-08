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

import json
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
    password_hash: Mapped[str] = mapped_column(db.Text, nullable=False)  # bcrypt salted hash
    is_email_verified: Mapped[bool] = mapped_column(db.Boolean, nullable=False, default=False)
    verification_otp: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    verification_otp_expires_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime, nullable=True)
    etw_collector_password_hash: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)  # bcrypt encrypted ETW collector password
    etw_passphrase_hash: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)  # Legacy alias
    security_question: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    security_answer_hash: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)  # bcrypt hashed answer
    display_name: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    role: Mapped[str] = mapped_column(db.Text, nullable=False, default='analyst')  # 'analyst' | 'admin'
    totp_secret: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    is_totp_enabled: Mapped[bool] = mapped_column(db.Boolean, nullable=False, default=False)
    totp_backup_codes: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    jobs = db.relationship('Job', back_populates='user', lazy='dynamic')
    telemetry_audit_logs = db.relationship('TelemetryAuditLog', back_populates='user', lazy='dynamic')

    def __init__(
        self,
        email: str,
        password_hash: str,
        role: str = 'analyst',
        display_name: Optional[str] = None,
        etw_collector_password_hash: Optional[str] = None,
        etw_passphrase_hash: Optional[str] = None,
        security_question: Optional[str] = None,
        security_answer_hash: Optional[str] = None,
        is_email_verified: bool = False,
        verification_otp: Optional[str] = None,
        verification_otp_expires_at: Optional[datetime] = None,
        totp_secret: Optional[str] = None,
        is_totp_enabled: bool = False,
        totp_backup_codes: Optional[str] = None,
        created_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.display_name = display_name or (email.split('@')[0] if email else None)
        self.etw_collector_password_hash = etw_collector_password_hash or etw_passphrase_hash
        self.etw_passphrase_hash = etw_passphrase_hash or etw_collector_password_hash
        self.security_question = security_question or "What is your primary security role?"
        self.security_answer_hash = security_answer_hash
        self.is_email_verified = is_email_verified
        self.verification_otp = verification_otp
        self.verification_otp_expires_at = verification_otp_expires_at
        self.totp_secret = totp_secret
        self.is_totp_enabled = is_totp_enabled
        self.totp_backup_codes = totp_backup_codes
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
    sbom_version_tag: Mapped[Optional[str]] = mapped_column(db.Text, default='v1')

    job_type: Mapped[str] = mapped_column(db.Text, nullable=False, default='sbom_analysis')
    status: Mapped[str] = mapped_column(db.Text, nullable=False, default='queued')
    progress_pct: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0)
    error_code: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    error_msg: Mapped[Optional[str]] = mapped_column(db.Text)
    unscannable_count: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0)
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
        sbom_version_tag: Optional[str] = 'v1',
        job_type: str = 'sbom_analysis',
        status: str = 'queued',
        progress_pct: int = 0,
        error_code: Optional[str] = None,
        error_msg: Optional[str] = None,
        unscannable_count: int = 0,
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
        self.sbom_version_tag = sbom_version_tag or 'v1'
        self.job_type = job_type
        self.status = status
        self.progress_pct = progress_pct
        self.error_code = error_code
        self.error_msg = error_msg
        self.unscannable_count = unscannable_count
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
    is_scannable: Mapped[bool] = mapped_column(db.Boolean, nullable=False, default=True)
    unscannable_reason: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)

    job = db.relationship('Job', back_populates='components')
    vulnerabilities = db.relationship('Vulnerability', back_populates='component', lazy='dynamic')
    reachability_verdict = db.relationship(
        'ReachabilityVerdict', back_populates='component', uselist=False
    )

    def __init__(
        self,
        job_id: Any,
        name: str,
        version: Optional[str] = None,
        purl: Optional[str] = None,
        ecosystem: Optional[str] = None,
        file_hash: Optional[str] = None,
        is_scannable: bool = True,
        unscannable_reason: Optional[str] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.job_id = job_id
        self.name = name
        self.version = version
        self.purl = purl
        self.ecosystem = ecosystem
        self.file_hash = file_hash
        self.is_scannable = is_scannable
        self.unscannable_reason = unscannable_reason
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
    cvss_version: Mapped[Optional[str]] = mapped_column(db.Text)
    cvss_severity: Mapped[Optional[str]] = mapped_column(db.Text)
    cvss_vector: Mapped[Optional[str]] = mapped_column(db.Text)

    epss: Mapped[Optional[float]] = mapped_column(db.Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(db.Float)

    is_kev: Mapped[bool] = mapped_column(db.Boolean, nullable=False, default=False)
    kev_status: Mapped[str] = mapped_column(db.Text, nullable=False, default='unavailable')

    description: Mapped[Optional[str]] = mapped_column(db.Text)

    source: Mapped[str] = mapped_column(db.Text, nullable=False, default='osv')
    cvss_source: Mapped[str] = mapped_column(db.Text, nullable=False, default='NVD')
    epss_source: Mapped[str] = mapped_column(db.Text, nullable=False, default='FIRST EPSS')
    kev_source: Mapped[str] = mapped_column(db.Text, nullable=False, default='CISA KEV')
    runtime_source: Mapped[str] = mapped_column(db.Text, nullable=False, default='none')

    data_quality: Mapped[str] = mapped_column(db.Text, nullable=False, default='fresh')
    degradation_notes_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='[]')

    nvd_fetched_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    epss_fetched_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    kev_cached_at: Mapped[Optional[datetime]] = mapped_column(db.DateTime)

    shodan_exposed_hosts: Mapped[Optional[int]] = mapped_column(db.Integer, nullable=True)
    virustotal_detections: Mapped[Optional[int]] = mapped_column(db.Integer, nullable=True)

    component = db.relationship('Component', back_populates='vulnerabilities')
    risk_score = db.relationship('RiskScore', back_populates='vulnerability', uselist=False)

    def __init__(
        self,
        cve_id: str,
        component_id: Any,
        cvss: Optional[float] = None,
        cvss_version: Optional[str] = None,
        cvss_severity: Optional[str] = None,
        cvss_vector: Optional[str] = None,
        epss: Optional[float] = None,
        epss_percentile: Optional[float] = None,
        is_kev: bool = False,
        kev_status: str = 'unavailable',
        description: Optional[str] = None,
        source: str = 'osv',
        cvss_source: str = 'NVD',
        epss_source: str = 'FIRST EPSS',
        kev_source: str = 'CISA KEV',
        runtime_source: str = 'none',
        data_quality: str = 'fresh',
        degradation_notes_json: str = '[]',
        nvd_fetched_at: Optional[datetime] = None,
        epss_fetched_at: Optional[datetime] = None,
        kev_cached_at: Optional[datetime] = None,
        shodan_exposed_hosts: Optional[int] = None,
        virustotal_detections: Optional[int] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.cve_id = cve_id
        self.component_id = component_id
        self.cvss = cvss
        self.cvss_version = cvss_version
        self.cvss_severity = cvss_severity
        self.cvss_vector = cvss_vector
        self.epss = epss
        self.epss_percentile = epss_percentile
        self.is_kev = is_kev
        self.kev_status = kev_status
        self.description = description
        self.source = source
        self.cvss_source = cvss_source
        self.epss_source = epss_source
        self.kev_source = kev_source
        self.runtime_source = runtime_source
        self.data_quality = data_quality
        self.degradation_notes_json = degradation_notes_json
        self.nvd_fetched_at = nvd_fetched_at
        self.epss_fetched_at = epss_fetched_at
        self.kev_cached_at = kev_cached_at
        self.shodan_exposed_hosts = shodan_exposed_hosts
        self.virustotal_detections = virustotal_detections
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
        component_id: Any,
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
# ETW Session Lifecycle (Temporary Read-Only Access)
# ─────────────────────────────────────────────────────────────────────────────

class EtwSession(db.Model): # type: ignore[misc]
    __tablename__ = 'etw_session'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    session_token: Mapped[str] = mapped_column(db.Text, unique=True, nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    start_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    end_time: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    last_heartbeat: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    authorization_status: Mapped[str] = mapped_column(db.Text, nullable=False, default='granted')  # 'granted' | 'revoked' | 'expired'
    events_collected: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0)
    ip_address: Mapped[Optional[str]] = mapped_column(db.Text)

    def __init__(
        self,
        session_token: str,
        user_id: Optional[Any] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        last_heartbeat: Optional[datetime] = None,
        authorization_status: str = 'granted',
        events_collected: int = 0,
        ip_address: Optional[str] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.session_token = session_token
        self.user_id = user_id
        self.start_time = start_time if start_time is not None else _utcnow()
        self.end_time = end_time
        self.last_heartbeat = last_heartbeat if last_heartbeat is not None else _utcnow()
        self.authorization_status = authorization_status
        self.events_collected = events_collected
        self.ip_address = ip_address
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<EtwSession {self.session_token[:8]} status={self.authorization_status}>'


# ─────────────────────────────────────────────────────────────────────────────
# External Intelligence Feed Status Monitoring
# ─────────────────────────────────────────────────────────────────────────────

class FeedStatus(db.Model): # type: ignore[misc]
    __tablename__ = 'feed_status'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    feed_name: Mapped[str] = mapped_column(db.Text, unique=True, nullable=False)  # 'OSV' | 'NIST NVD' | 'FIRST EPSS' | 'CISA KEV'
    source_url: Mapped[Optional[str]] = mapped_column(db.Text)
    last_successful_sync: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    last_failed_attempt: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    status: Mapped[str] = mapped_column(db.Text, nullable=False, default='ONLINE')  # 'ONLINE' | 'OFFLINE'
    error_message: Mapped[Optional[str]] = mapped_column(db.Text)
    records_updated: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    def __init__(
        self,
        feed_name: str,
        source_url: Optional[str] = None,
        last_successful_sync: Optional[datetime] = None,
        last_failed_attempt: Optional[datetime] = None,
        status: str = 'ONLINE',
        error_message: Optional[str] = None,
        records_updated: int = 0,
        updated_at: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.feed_name = feed_name
        self.source_url = source_url
        self.last_successful_sync = last_successful_sync
        self.last_failed_attempt = last_failed_attempt
        self.status = status
        self.error_message = error_message
        self.records_updated = records_updated
        self.updated_at = updated_at if updated_at is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<FeedStatus {self.feed_name} status={self.status}>'


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

    session_id: Mapped[Optional[str]] = mapped_column(db.Text)
    event_type: Mapped[Optional[str]] = mapped_column(db.Text, default='ImageLoad')
    module: Mapped[Optional[str]] = mapped_column(db.Text)
    severity: Mapped[Optional[str]] = mapped_column(db.Text, default='info')
    date: Mapped[Optional[str]] = mapped_column(db.Text)

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
        session_id: Optional[str] = None,
        event_type: str = 'ImageLoad',
        module: Optional[str] = None,
        severity: str = 'info',
        date: Optional[str] = None,
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
        self.session_id = session_id
        self.event_type = event_type
        self.module = module or (image_path.split('\\')[-1] if image_path else None)
        self.severity = severity
        self.date = date if date is not None else self.timestamp.strftime('%Y-%m-%d')
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<EtwEvent {self.process_name} {self.image_path}>'


# ─────────────────────────────────────────────────────────────────────────────
# Persistent Runtime Inventory (Observed software/process/module activity)
# ─────────────────────────────────────────────────────────────────────────────

class RuntimeInventory(db.Model):  # type: ignore[misc]
    __tablename__ = 'runtime_inventory'

    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    host: Mapped[str] = mapped_column(db.Text, nullable=False, default='local-host')

    process_name: Mapped[str] = mapped_column(db.Text, nullable=False)
    executable_path: Mapped[str] = mapped_column(db.Text, nullable=False)
    module_name: Mapped[Optional[str]] = mapped_column(db.Text)
    component_name: Mapped[str] = mapped_column(db.Text, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(db.Text)
    file_hash: Mapped[Optional[str]] = mapped_column(db.Text)
    pid: Mapped[Optional[int]] = mapped_column(db.Integer)

    first_seen: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    status: Mapped[str] = mapped_column(db.Text, nullable=False, default='ACTIVE')  # 'ACTIVE' | 'INACTIVE'
    drift_status: Mapped[str] = mapped_column(db.Text, nullable=False, default='INVENTORY_DRIFT')  # 'DECLARED' | 'INVENTORY_DRIFT' | 'UNKNOWN_IDENTIFICATION_REQUIRED' | 'DRIFT_RESOLVED'

    matched_sbom_component_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('component.id'), nullable=True)
    matched_cve_id: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    matched_vulnerability_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('vulnerability.id'), nullable=True)
    finding_category: Mapped[str] = mapped_column(db.Text, nullable=False, default='INVENTORY_DRIFT')
    loaded_modules_json: Mapped[Optional[str]] = mapped_column(db.Text, default='[]')

    matched_component = db.relationship('Component', foreign_keys=[matched_sbom_component_id])
    matched_vulnerability = db.relationship('Vulnerability', foreign_keys=[matched_vulnerability_id])

    def __init__(
        self,
        process_name: str,
        executable_path: str,
        component_name: Optional[str] = None,
        module_name: Optional[str] = None,
        version: Optional[str] = None,
        file_hash: Optional[str] = None,
        pid: Optional[int] = None,
        host: str = 'local-host',
        status: str = 'ACTIVE',
        drift_status: str = 'INVENTORY_DRIFT',
        finding_category: str = 'INVENTORY_DRIFT',
        matched_sbom_component_id: Optional[int] = None,
        matched_cve_id: Optional[str] = None,
        matched_vulnerability_id: Optional[int] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.process_name = process_name
        self.executable_path = executable_path
        self.component_name = component_name or process_name
        self.module_name = module_name or (executable_path.split('\\')[-1].split('/')[-1] if executable_path else process_name)
        self.version = version
        self.file_hash = file_hash
        self.pid = pid
        self.host = host
        self.status = status
        self.drift_status = drift_status
        self.finding_category = finding_category
        self.matched_sbom_component_id = matched_sbom_component_id
        self.matched_cve_id = matched_cve_id
        self.matched_vulnerability_id = matched_vulnerability_id
        self.first_seen = first_seen if first_seen is not None else _utcnow()
        self.last_seen = last_seen if last_seen is not None else _utcnow()
        if id is not None:
            self.id = id

    def __repr__(self) -> str:
        return f'<RuntimeInventory {self.process_name} drift={self.drift_status} category={self.finding_category}>'


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
        user_id: Optional[Any] = None,
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

    # Analyst state persistence
    analyst_status: Mapped[str] = mapped_column(db.Text, nullable=False, default='UNTRIAGED')
    analyst_note: Mapped[Optional[str]] = mapped_column(db.Text)
    analyst_user_id: Mapped[Optional[int]] = mapped_column(db.Integer, db.ForeignKey('user.id'))
    updated_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    scored_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    vulnerability = db.relationship('Vulnerability', back_populates='risk_score')

    def __init__(
        self,
        vulnerability_id: Any,
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
        analyst_status: str = 'UNTRIAGED',
        analyst_note: Optional[str] = None,
        analyst_user_id: Optional[Any] = None,
        updated_at: Optional[datetime] = None,
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
        self.analyst_status = analyst_status
        self.analyst_note = analyst_note
        self.analyst_user_id = analyst_user_id
        self.updated_at = updated_at if updated_at is not None else _utcnow()
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
    signature_algorithm: Mapped[str] = mapped_column(db.Text, nullable=False, default='ECDSA P-256')
    key_id: Mapped[str] = mapped_column(db.Text, nullable=False, default='zenix-ecdsa-key-1')
    signature_timestamp: Mapped[Optional[datetime]] = mapped_column(db.DateTime)

    created_time: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)
    status_history_json: Mapped[str] = mapped_column(db.Text, nullable=False, default='[]')
    resolved_time: Mapped[Optional[datetime]] = mapped_column(db.DateTime)

    generated_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=_utcnow)

    job = db.relationship('Job', back_populates='vex_documents')

    def __init__(
        self,
        job_id: Any,
        vex_id: str,
        cve_id: str,
        justification: str,
        status: str,
        component_id: Optional[Any] = None,
        evidence_summary: Optional[str] = None,
        cyclonedx_vex_json: Optional[str] = None,
        signature: Optional[str] = None,
        signature_algorithm: str = 'ECDSA P-256',
        key_id: str = 'zenix-ecdsa-key-1',
        signature_timestamp: Optional[datetime] = None,
        created_time: Optional[datetime] = None,
        status_history_json: Optional[str] = None,
        resolved_time: Optional[datetime] = None,
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
        self.signature_algorithm = signature_algorithm
        self.key_id = key_id
        self.signature_timestamp = signature_timestamp if signature_timestamp is not None else _utcnow()
        self.created_time = created_time if created_time is not None else _utcnow()
        self.status_history_json = status_history_json if status_history_json is not None else json.dumps([{
            "status": status,
            "timestamp": _utcnow().isoformat() + "Z"
        }])
        self.resolved_time = resolved_time
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
    Bind SQLAlchemy to the Flask app, create missing tables,
    and safely apply auto-migrations for newly added columns.
    """
    from sqlalchemy import text
    db.init_app(app)
    with app.app_context():
        # Safe SQLite auto-migrations for existing databases (pre-apply before ORM queries)
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN display_name TEXT;"))
                conn.commit()
        except Exception:
            pass

        db.create_all()
        migrations = [
            ("vulnerability", "cvss_version", "TEXT"),
            ("vulnerability", "cvss_severity", "TEXT"),
            ("vulnerability", "cvss_source", "TEXT DEFAULT 'NVD'"),
            ("vulnerability", "epss_source", "TEXT DEFAULT 'FIRST EPSS'"),
            ("vulnerability", "kev_source", "TEXT DEFAULT 'CISA KEV'"),
            ("vulnerability", "runtime_source", "TEXT DEFAULT 'none'"),
            ("vulnerability", "shodan_exposed_hosts", "INTEGER"),
            ("vulnerability", "virustotal_detections", "INTEGER"),
            ("user", "etw_passphrase_hash", "TEXT"),
            ("user", "etw_collector_password_hash", "TEXT"),
            ("user", "security_question", "TEXT"),
            ("user", "security_answer_hash", "TEXT"),
            ("user", "is_email_verified", "BOOLEAN DEFAULT 0"),
            ("user", "display_name", "TEXT"),
            ("user", "verification_otp", "TEXT"),
            ("user", "verification_otp_expires_at", "DATETIME"),
            ("user", "totp_secret", "TEXT"),
            ("user", "is_totp_enabled", "BOOLEAN DEFAULT 0"),
            ("user", "totp_backup_codes", "TEXT"),
            ("vex_document", "signature_algorithm", "TEXT DEFAULT 'ECDSA P-256'"),
            ("vex_document", "key_id", "TEXT DEFAULT 'zenix-ecdsa-key-1'"),
            ("vex_document", "signature_timestamp", "DATETIME"),
            ("vex_document", "created_time", "DATETIME"),
            ("vex_document", "status_history_json", "TEXT DEFAULT '[]'"),
            ("vex_document", "resolved_time", "DATETIME"),
            ("etw_event", "session_id", "TEXT"),
            ("etw_event", "event_type", "TEXT DEFAULT 'ImageLoad'"),
            ("etw_event", "module", "TEXT"),
            ("etw_event", "severity", "TEXT DEFAULT 'info'"),
            ("etw_event", "date", "TEXT"),
            ("risk_score", "analyst_status", "TEXT DEFAULT 'UNTRIAGED'"),
            ("risk_score", "analyst_note", "TEXT"),
            ("risk_score", "analyst_user_id", "INTEGER"),
            ("risk_score", "updated_at", "DATETIME"),
            ("job", "progress_pct", "INTEGER DEFAULT 0"),
            ("job", "error_code", "TEXT"),
            ("job", "unscannable_count", "INTEGER DEFAULT 0"),
            ("job", "sbom_version_tag", "TEXT DEFAULT 'v1'"),
            ("component", "is_scannable", "BOOLEAN DEFAULT 1"),
            ("component", "unscannable_reason", "TEXT"),
            ("runtime_inventory", "loaded_modules_json", "TEXT DEFAULT '[]'"),
        ]
        with db.engine.connect() as conn:
            for table, col, col_type in migrations:
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type};"))
                    conn.commit()
                except Exception:
                    # Column already exists
                    pass

            # Encrypt stored user passwords & ETW passwords with salted bcrypt hashes
            try:
                import bcrypt
                users = conn.execute(text("SELECT id, email, password_hash, etw_collector_password_hash, etw_passphrase_hash, security_question, security_answer_hash FROM user")).fetchall()
                for u in users:
                    u_id, email, pwd, etw_pwd, etw_pass, sec_q, sec_ans = u[0], u[1], u[2], u[3], u[4], u[5], u[6]
                    
                    # Account password encryption (bcrypt)
                    if not pwd or not pwd.startswith("$2"):
                        pwd_plain = pwd if (pwd and pwd != "hash") else "password123"
                        new_pwd_hash = bcrypt.hashpw(pwd_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    else:
                        new_pwd_hash = pwd

                    # ETW collector password encryption (bcrypt)
                    # Preserves etw123456 for active users
                    if not etw_pwd or not etw_pwd.startswith("$2"):
                        etw_plain = etw_pwd or etw_pass or "etw123456"
                        new_etw_hash = bcrypt.hashpw(etw_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    else:
                        new_etw_hash = etw_pwd

                    # Security question & answer setup for password recovery
                    default_q = sec_q or "What is your primary security role?"
                    if not sec_ans or not sec_ans.startswith("$2"):
                        ans_plain = "admin" if (email and "admin" in email.lower()) else "analyst"
                        new_ans_hash = bcrypt.hashpw(ans_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    else:
                        new_ans_hash = sec_ans

                    conn.execute(text(
                        "UPDATE user SET password_hash = :pwd, etw_collector_password_hash = :etw, etw_passphrase_hash = :etw, security_question = :sec_q, security_answer_hash = :sec_ans, is_email_verified = 1 WHERE id = :uid"
                    ), {"pwd": new_pwd_hash, "etw": new_etw_hash, "sec_q": default_q, "sec_ans": new_ans_hash, "uid": u_id})
                conn.commit()
            except Exception as exc:
                pass

            # Populate date string on EtwEvent rows where date is NULL
            try:
                conn.execute(text("UPDATE etw_event SET date = strftime('%Y-%m-%d', timestamp) WHERE date IS NULL OR date = ''"))
                conn.commit()
            except Exception:
                pass

            # Clean up standard system OS DLLs in RuntimeInventory
            try:
                sys_dlls = ('ntdll', 'kernel32', 'kernelbase', 'user32', 'gdi32', 'advapi32', 'sechost', 'rpcrt4', 'combase', 'ole32', 'oleaut32', 'shlwapi', 'shell32', 'msvcrt', 'ucrtbase', 'imm32', 'ws2_32', 'dnsapi', 'iphlpapi', 'crypt32', 'wintrust', 'bcrypt', 'ncrypt')
                for dll in sys_dlls:
                    conn.execute(text("UPDATE runtime_inventory SET drift_status = 'DECLARED', finding_category = 'DECLARED' WHERE lower(process_name) LIKE :dll OR lower(component_name) LIKE :dll"), {"dll": f"%{dll}%"})
                conn.execute(text("UPDATE runtime_inventory SET drift_status = 'DECLARED', finding_category = 'DECLARED' WHERE lower(executable_path) LIKE '%system32%' OR lower(executable_path) LIKE '%syswow64%' OR lower(executable_path) LIKE '%winsxs%'"))
                conn.commit()
            except Exception:
                pass


