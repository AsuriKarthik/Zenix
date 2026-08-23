"""
Tests for Part A (Filesystem Read-Only Isolation) & Part B (Passphrase Gate & Audit Logging).

Coverage:
  - Part A: Read-only SQLite URI connection rejects unprivileged write operations to EtwEvent.
  - Part B1: ETW Collector is disabled by default on startup (No Auto-Start).
  - Part B2: Enabling ETW requires correct secondary administrative passphrase.
  - Part B3: Invalid passphrase returns 401 Unauthorized and logs TelemetryAuditLog entry.
  - Part B4: Repeated invalid passphrase attempts trigger IP lockout (429 Too Many Requests).
  - Part B5: Every enable/disable action is recorded in TelemetryAuditLog DB table.
"""

import sqlite3
import pytest
from flask import Flask

from db import db, User, EtwEvent, TelemetryAuditLog
from agents.etw_collector import etw_collector, ETWCollector
from api.telemetry import clear_failed_etw_attempts


class TestPartAEtwFilesystemIsolation:

    def test_readonly_sqlite_connection_rejects_unprivileged_writes(self, tmp_path):
        """Unprivileged read-only connection to EtwEvent DB rejects write operations."""
        db_file = tmp_path / "etw_events.db"

        # 1. Privileged creation
        conn_admin = sqlite3.connect(str(db_file))
        conn_admin.execute("CREATE TABLE etw_event (id INTEGER PRIMARY KEY, image_path TEXT, evidence_source TEXT)")
        conn_admin.execute("INSERT INTO etw_event (image_path, evidence_source) VALUES ('C:\\\\path.dll', 'etw')")
        conn_admin.commit()
        conn_admin.close()

        # 2. Unprivileged Read-Only Connection (mode=ro)
        uri = f"file:{db_file.as_posix()}?mode=ro&uri=true"
        conn_ro = sqlite3.connect(uri, uri=True)
        cursor_ro = conn_ro.cursor()

        # SELECT works cleanly
        cursor_ro.execute("SELECT * FROM etw_event")
        rows = cursor_ro.fetchall()
        assert len(rows) == 1

        # INSERT fails with sqlite3.OperationalError: attempt to write a readonly database
        with pytest.raises(sqlite3.OperationalError) as exc_info:
            cursor_ro.execute("INSERT INTO etw_event (image_path, evidence_source) VALUES ('C:\\\\fake.dll', 'etw')")

        assert "readonly" in str(exc_info.value).lower()
        conn_ro.close()


class TestPartBEtwPassphraseGateAndAuditLogging:

    def test_etw_collector_disabled_by_default_on_startup(self):
        collector = ETWCollector()
        status = collector.get_status()
        assert status["running"] is False

    def test_enable_etw_with_valid_passphrase(self, app, db_session):
        client = app.test_client()

        # Register, Login & configure ETW Collector Password
        client.post('/api/auth/register', json={"email": "admin_etw@zenix.io", "password": "Password123!", "role": "admin"})
        client.post('/api/auth/login', json={"email": "admin_etw@zenix.io", "password": "Password123!"})
        client.post('/api/auth/setup-etw-password', json={"etw_collector_password": "SecretETWPass123!"})

        # Allow test override for elevated state
        etw_collector.is_available = True

        res = client.post('/api/telemetry/enable', json={"passphrase": "SecretETWPass123!"})
        assert res.status_code == 200
        assert "enabled successfully" in res.get_json()["message"]
        assert etw_collector.get_status()["running"] is True

        # Verify audit log entry created
        audit_entry = TelemetryAuditLog.query.filter_by(action='enable', result='success').first()
        assert audit_entry is not None
        assert audit_entry.user_id is not None

        # Clean up
        etw_collector.stop()

    def test_enable_etw_with_invalid_passphrase_fails(self, app, db_session):
        client = app.test_client()
        clear_failed_etw_attempts('127.0.0.1')

        client.post('/api/auth/register', json={"email": "user_etw@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "user_etw@zenix.io", "password": "Password123!"})
        client.post('/api/auth/setup-etw-password', json={"etw_collector_password": "SecretETWPass123!"})

        res = client.post('/api/telemetry/enable', json={"passphrase": "WrongPassphrase123"})
        assert res.status_code == 401
        assert "Invalid" in res.get_json()["error"]

        # Verify audit log entry created for failure
        audit_entry = TelemetryAuditLog.query.filter_by(action='enable', result='auth_failed').first()
        assert audit_entry is not None

    def test_passphrase_rate_limiting_locks_out_after_5_failures(self, app, db_session):
        client = app.test_client()
        clear_failed_etw_attempts('127.0.0.1')

        client.post('/api/auth/register', json={"email": "user_etw2@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "user_etw2@zenix.io", "password": "Password123!"})

        # Make 5 failed passphrase attempts
        for i in range(5):
            res = client.post('/api/telemetry/enable', json={"passphrase": f"BadPassphrase{i}"})
            assert res.status_code == 401

        # 6th attempt blocked with 429
        res_blocked = client.post('/api/telemetry/enable', json={"passphrase": "ZenixETWAdmin2026!"})
        assert res_blocked.status_code == 429
        assert "Locked out" in res_blocked.get_json()["error"]

        # Clean up
        clear_failed_etw_attempts('127.0.0.1')

    def test_disable_etw_logs_audit_entry(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "user_etw3@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "user_etw3@zenix.io", "password": "Password123!"})

        res = client.post('/api/telemetry/disable')
        assert res.status_code == 200

        audit_entry = TelemetryAuditLog.query.filter_by(action='disable', result='success').first()
        assert audit_entry is not None
