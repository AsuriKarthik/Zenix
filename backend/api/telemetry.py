"""
Telemetry API Endpoints — Part A (Filesystem Read-Only Protection) + Part B (Secondary Passphrase Gate & Audit Logging).

Endpoints:
  GET /api/telemetry/status — Return telemetry collector status & active mode.
  GET /api/telemetry/events — Return telemetry events.
  POST /api/telemetry/enable — Enable ETW collector using secondary admin passphrase (rate-limited, audit logged).
  POST /api/telemetry/disable — Disable ETW collector (audit logged).
  GET /api/telemetry/audit-logs — Query telemetry activation audit history.
"""

from __future__ import annotations

import time
import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

import bcrypt
from config import Config
from agents.etw_collector import etw_collector
from db import db, EtwEvent, TelemetryAuditLog

telemetry_bp = Blueprint('telemetry', __name__, url_prefix='/api/telemetry')
log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────────────────────────────────────
# Part B: Passphrase Rate Limiter for ETW Enablement
# ─────────────────────────────────────────────────────────────────────────────

_FAILED_ETW_PASSPHRASE_ATTEMPTS: dict[str, list[float]] = {}


def _clean_old_etw_attempts(ip: str, window_seconds: float = 900.0) -> list[float]:
    now = time.monotonic()
    attempts = [t for t in _FAILED_ETW_PASSPHRASE_ATTEMPTS.get(ip, []) if now - t < window_seconds]
    _FAILED_ETW_PASSPHRASE_ATTEMPTS[ip] = attempts
    return attempts


def is_etw_passphrase_locked(ip: str) -> tuple[bool, int]:
    attempts = _clean_old_etw_attempts(ip)
    max_attempts = getattr(Config, 'LOGIN_MAX_FAILED_ATTEMPTS', 5)
    lockout_seconds = getattr(Config, 'LOGIN_LOCKOUT_SECONDS', 300)

    if len(attempts) >= max_attempts:
        newest = max(attempts)
        elapsed = time.monotonic() - newest
        if elapsed < lockout_seconds:
            remaining = int(lockout_seconds - elapsed)
            return True, max(remaining, 1)

    return False, 0


def record_failed_etw_attempt(ip: str) -> None:
    attempts = _clean_old_etw_attempts(ip)
    attempts.append(time.monotonic())
    _FAILED_ETW_PASSPHRASE_ATTEMPTS[ip] = attempts


def clear_failed_etw_attempts(ip: str) -> None:
    _FAILED_ETW_PASSPHRASE_ATTEMPTS.pop(ip, None)


# Default secondary ETW passphrase hash if not set in environment (Passphrase: "ZenixETWAdmin2026!")
_DEFAULT_ETW_PASSPHRASE_HASH = bcrypt.hashpw(b"ZenixETWAdmin2026!", bcrypt.gensalt()).decode('utf-8')


def verify_etw_passphrase(passphrase: str) -> bool:
    """Verify provided passphrase against bcrypt hash."""
    target_hash = getattr(Config, 'ETW_ADMIN_PASSPHRASE_HASH', '') or _DEFAULT_ETW_PASSPHRASE_HASH
    try:
        return bcrypt.checkpw(passphrase.encode('utf-8'), target_hash.encode('utf-8'))
    except Exception:
        return False


def _log_audit_entry(action: str, result: str, ip: str, user_id: int | None, details: str = '') -> TelemetryAuditLog:
    """Write an entry to TelemetryAuditLog DB table."""
    audit = TelemetryAuditLog(
        action=action,
        result=result,
        ip_address=ip,
        user_id=user_id,
        details=details,
        timestamp=_utcnow(),
    )
    db.session.add(audit)
    db.session.commit()
    return audit


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@telemetry_bp.route('/status', methods=['GET'])
@login_required
def get_telemetry_status():
    """
    Return current telemetry agent status, mode ('etw' | 'psutil'), elevation state, and event metrics.
    """
    status = etw_collector.get_status()
    return jsonify(status), 200


@telemetry_bp.route('/events', methods=['GET'])
@login_required
def get_telemetry_events():
    """
    Return telemetry event logs.
    """
    limit = request.args.get('limit', default=100, type=int)
    evidence_source = request.args.get('evidence_source')

    results = []

    try:
        etw_rows = EtwEvent.query.order_by(db.desc(EtwEvent.timestamp)).limit(limit).all()
        for evt in etw_rows:
            if evidence_source and evt.evidence_source != evidence_source:
                continue
            results.append({
                "id": evt.id,
                "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
                "pid": evt.pid,
                "process_name": evt.process_name,
                "image_path": evt.image_path,
                "image_hash": evt.image_hash,
                "evidence_source": evt.evidence_source,
                "confidence": "high" if evt.evidence_source == "etw" else "medium",
            })
    except Exception as exc:
        log.warning("Could not read EtwEvent table: %s", exc)

    return jsonify(results), 200


@telemetry_bp.route('/enable', methods=['POST'])
@login_required
def enable_etw_telemetry():
    """
    Part B: Require secondary administrative passphrase before enabling ETW collector.
    Rate limited (5 failures -> 5 min lockout) and audit logged.
    """
    client_ip = request.remote_addr or '127.0.0.1'
    user_id = current_user.id if current_user.is_authenticated else None

    # 1. Rate-limiting check
    locked, remaining_secs = is_etw_passphrase_locked(client_ip)
    if locked:
        _log_audit_entry('enable', 'rate_limited', client_ip, user_id, f"Blocked due to rate limit ({remaining_secs}s remaining)")
        return jsonify({
            "error": f"Too many failed ETW passphrase attempts. Locked out for {remaining_secs} seconds."
        }), 429

    # 2. Extract passphrase from request
    data = request.get_json() or {}
    passphrase = data.get('passphrase', '')

    if not passphrase:
        _log_audit_entry('enable', 'auth_failed', client_ip, user_id, "Missing passphrase")
        return jsonify({"error": "Secondary administrative passphrase is required to enable ETW telemetry."}), 400

    # 3. Verify passphrase
    if not verify_etw_passphrase(passphrase):
        record_failed_etw_attempt(client_ip)
        attempts = len(_FAILED_ETW_PASSPHRASE_ATTEMPTS.get(client_ip, []))
        _log_audit_entry('enable', 'auth_failed', client_ip, user_id, f"Invalid passphrase (attempt {attempts}/5)")
        return jsonify({
            "error": "Invalid secondary administrative passphrase.",
            "attempts_remaining": max(0, 5 - attempts)
        }), 401

    # 4. Correct passphrase -> clear failed attempts & attempt ETW start
    clear_failed_etw_attempts(client_ip)

    success = etw_collector.start()
    if not success:
        _log_audit_entry('enable', 'elevation_failed', client_ip, user_id, "Elevated Windows privileges absent")
        return jsonify({
            "error": "ETW enablement failed: Process lacks elevated Administrator privileges on Windows.",
            "status": etw_collector.get_status()
        }), 403

    _log_audit_entry('enable', 'success', client_ip, user_id, "ETW Telemetry collector enabled successfully")
    return jsonify({
        "message": "ETW Telemetry collector enabled successfully.",
        "status": etw_collector.get_status()
    }), 200


@telemetry_bp.route('/disable', methods=['POST'])
@login_required
def disable_etw_telemetry():
    """
    Part B: Disable ETW collector session and log audit entry.
    """
    client_ip = request.remote_addr or '127.0.0.1'
    user_id = current_user.id if current_user.is_authenticated else None

    etw_collector.stop()
    _log_audit_entry('disable', 'success', client_ip, user_id, "ETW Telemetry collector disabled")

    return jsonify({
        "message": "ETW Telemetry collector disabled.",
        "status": etw_collector.get_status()
    }), 200


@telemetry_bp.route('/audit-logs', methods=['GET'])
@login_required
def get_telemetry_audit_logs():
    """
    Return audit history of ETW activation/deactivation attempts.
    """
    if current_user.role == 'admin':
        logs = TelemetryAuditLog.query.order_by(db.desc(TelemetryAuditLog.timestamp)).limit(100).all()
    else:
        logs = TelemetryAuditLog.query.filter_by(user_id=current_user.id).order_by(db.desc(TelemetryAuditLog.timestamp)).all()

    results = []
    for l in logs:
        results.append({
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "user_id": l.user_id,
            "action": l.action,
            "result": l.result,
            "ip_address": l.ip_address,
            "details": l.details,
        })

    return jsonify(results), 200
