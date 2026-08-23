"""
Tests for Security Requirements 3, 4, 5, 6, 7.

Coverage:
  - Requirement 3: Asymmetric ECDSA VEX Report Signing & Public Key Export
  - Requirement 4: Login Rate Limiting (5 Failed Attempts -> 5 Minute IP Lockout)
  - Requirement 5: Session Cookie Security (HttpOnly, SameSite, Secure) & CSRF Token Validation
  - Requirement 6: Upload Limits (10MB Max Payload, Extension Check & JSON Pre-Validation)
  - Requirement 7: Strict User Data Isolation across Jobs, VEX Documents, and Results
"""

import json
import pytest
from flask import Flask

from config import Config
from db import db, User, Job, VexDocument
from api.auth import hash_password, clear_failed_attempts
from pipeline.vex_generator import (
    sign_vex_document,
    verify_vex_signature,
    get_vex_public_key_pem,
    get_vex_keypair,
)


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 3: Asymmetric ECDSA VEX Signing & Public Key Export
# ─────────────────────────────────────────────────────────────────────────────

class TestAsymmetricVexSigning:

    def test_ecdsa_public_key_export_pem(self):
        pem = get_vex_public_key_pem()
        assert isinstance(pem, str)
        assert 'BEGIN PUBLIC KEY' in pem

    def test_asymmetric_vex_signing_and_verification(self):
        doc_json = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "serialNumber": "urn:uuid:test-123"})
        keypair = get_vex_keypair()

        # Sign with private key
        sig_b64 = sign_vex_document(doc_json, keypair=keypair)
        assert isinstance(sig_b64, str)
        assert len(sig_b64) > 30

        # Verify with public key
        assert verify_vex_signature(doc_json, sig_b64, keypair=keypair) is True

        # Verify tampered document fails
        tampered_doc = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "serialNumber": "urn:uuid:tampered"})
        assert verify_vex_signature(tampered_doc, sig_b64, keypair=keypair) is False

        # Verify forged signature fails
        assert verify_vex_signature(doc_json, "invalid_base64_sig==", keypair=keypair) is False

    def test_public_key_api_endpoint(self, app, db_session):
        client = app.test_client()
        res = client.get('/api/vex/public-key')

        assert res.status_code == 200
        assert 'BEGIN PUBLIC KEY' in res.get_data(as_text=True)


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 4: Login Rate Limiting (Brute-Force Protection)
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginRateLimiting:

    def test_login_rate_limiting_locks_ip_after_5_failures(self, app, db_session):
        client = app.test_client()
        ip = '127.0.0.1'
        clear_failed_attempts(ip)

        # Register user
        client.post('/api/auth/register', json={"email": "target@zenix.io", "password": "Password123!"})

        # Make 5 failed attempts
        for i in range(5):
            res = client.post('/api/auth/login', json={"email": "target@zenix.io", "password": f"WrongPwd{i}"})
            assert res.status_code == 401

        # 6th attempt should be blocked with 429 Too Many Requests
        res_blocked = client.post('/api/auth/login', json={"email": "target@zenix.io", "password": "Password123!"})
        assert res_blocked.status_code == 429
        assert "Too many failed login attempts" in res_blocked.get_json()["error"]

        # Clean up
        clear_failed_attempts(ip)


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 5: Session Cookie Security & CSRF Token Protection
# ─────────────────────────────────────────────────────────────────────────────

class TestCookieAndCsrfSecurity:

    def test_session_cookie_security_flags(self, app):
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True
        assert app.config['SESSION_COOKIE_SAMESITE'] in ('Lax', 'Strict')

    def test_csrf_token_endpoint(self, app, db_session):
        client = app.test_client()
        res = client.get('/api/auth/csrf-token')

        assert res.status_code == 200
        data = res.get_json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) == 64

    def test_security_headers_middleware(self, app, db_session):
        client = app.test_client()
        res = client.get('/api/auth/csrf-token')

        assert res.headers.get('X-Content-Type-Options') == 'nosniff'
        assert res.headers.get('X-Frame-Options') == 'DENY'
        assert res.headers.get('X-XSS-Protection') == '1; mode=block'


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 6: Upload Limits & Pre-Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestUploadLimitsAndPreValidation:

    def test_upload_non_json_extension_rejected(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "uploader@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "uploader@zenix.io", "password": "Password123!"})

        res = client.post('/api/jobs/upload', headers={'X-File-Name': 'malicious.exe'}, data=b'echo 123')
        assert res.status_code == 400
        assert "Unsupported file type" in res.get_json()["error"]

    def test_malformed_json_upload_rejected_before_enqueue(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "uploader2@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "uploader2@zenix.io", "password": "Password123!"})

        res = client.post('/api/jobs/upload', headers={'X-File-Name': 'sbom.json'}, data=b'{ invalid json }')
        assert res.status_code == 400
        assert "not valid JSON" in res.get_json()["error"]

    def test_upload_exceeding_max_size_rejected(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "uploader3@zenix.io", "password": "Password123!"})
        client.post('/api/auth/login', json={"email": "uploader3@zenix.io", "password": "Password123!"})

        huge_payload = b'a' * (11 * 1024 * 1024)  # 11 MB
        res = client.post('/api/jobs/upload', headers={'X-File-Name': 'huge.json'}, data=huge_payload)
        assert res.status_code == 413


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 7: Strict User Data Isolation across ALL Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestUserDataIsolationAcrossAllEndpoints:

    def test_user_cannot_access_other_users_vex_documents(self, app, db_session):
        with app.app_context():
            u1 = User(email="user_a@zenix.io", password_hash=hash_password("Pass123!"), role="analyst")
            u2 = User(email="user_b@zenix.io", password_hash=hash_password("Pass123!"), role="analyst")
            db.session.add_all([u1, u2])
            db.session.commit()

            # pyrefly: ignore [bad-argument-type]
            j_b = Job(id="job-user-b", user_id=u2.id, sbom_format="cyclonedx-json", sbom_sha256="123", status="done")
            db.session.add(j_b)
            db.session.commit()

            doc_json = json.dumps({"bomFormat": "CycloneDX"})
            sig = sign_vex_document(doc_json)
            vex_b = VexDocument(
                job_id="job-user-b",
                vex_id="VEX-2026-USER-B",
                cve_id="CVE-2021-44228",
                justification="vulnerable_code_not_in_execute_path",
                status="not_affected",
                cyclonedx_vex_json=doc_json,
                signature=sig,
            )
            db.session.add(vex_b)
            db.session.commit()

        client = app.test_client()

        # Login as User A
        client.post('/api/auth/login', json={"email": "user_a@zenix.io", "password": "Pass123!"})

        # User A attempts to list VEX for User B's job -> returns empty list
        res_list = client.get('/api/vex?job_id=job-user-b')
        assert res_list.status_code == 200
        assert len(res_list.get_json()) == 0

        # User A attempts to download User B's VEX document -> 403 Forbidden
        res_dl = client.get('/api/vex/VEX-2026-USER-B/download')
        assert res_dl.status_code == 403
        assert "Unauthorized" in res_dl.get_json()["error"]
