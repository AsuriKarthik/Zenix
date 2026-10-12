"""
Tests for Step 9 — Authentication & Authorization Layer (bcrypt + Flask-Login).

Coverage:
  - Password hashing & verification correctness
  - User registration (/api/auth/register)
  - Login success & invalid credential rejection (/api/auth/login)
  - Protected routes rejection when unauthenticated (401 Unauthorized)
  - Role-based authorization isolation (Analyst vs Admin access)
  - Session logout (/api/auth/logout)
"""

import pytest
from flask import Flask

from db import db, User, Job
from api.auth import hash_password, check_password
from jobs.queue import JobQueue


class TestBcryptPasswordHashing:

    def test_hash_password_produces_bcrypt_string(self):
        pwd = "SecurePassword123!"
        pwd_hash = hash_password(pwd)

        assert isinstance(pwd_hash, str)
        assert pwd_hash.startswith("$2b$") or pwd_hash.startswith("$2a$")
        assert pwd_hash != pwd

    def test_check_password_validates_correctly(self):
        pwd = "CorrectPassword123"
        pwd_hash = hash_password(pwd)

        assert check_password(pwd, pwd_hash) is True
        assert check_password("WrongPassword123", pwd_hash) is False


class TestAuthAPIEndpoints:

    def test_register_user_success(self, app, db_session):
        client = app.test_client()
        res = client.post('/api/auth/register', json={
            "email": "newanalyst@zenix.io",
            "password": "Password123!",
            "role": "analyst"
        })

        assert res.status_code == 201
        data = res.get_json()
        assert "user" in data
        assert data["user"]["email"] == "newanalyst@zenix.io"

        # Verify DB entry
        user = User.query.filter_by(email="newanalyst@zenix.io").first()
        assert user is not None
        assert check_password("Password123!", user.password_hash) is True

    def test_register_duplicate_email_fails(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "dupe@zenix.io", "password": "Password123!"})

        res = client.post('/api/auth/register', json={"email": "dupe@zenix.io", "password": "Password123!"})
        assert res.status_code == 409
        assert "already exists" in res.get_json()["error"]

    def test_login_success_and_logout(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "user@zenix.io", "password": "Password123!"})

        # Login
        res_login = client.post('/api/auth/login', json={"email": "user@zenix.io", "password": "Password123!"})
        assert res_login.status_code == 200
        assert res_login.get_json()["user"]["email"] == "user@zenix.io"

        # /api/auth/me should succeed
        res_me = client.get('/api/auth/me')
        assert res_me.status_code == 200

        # Logout
        res_logout = client.post('/api/auth/logout')
        assert res_logout.status_code == 200

        # /api/auth/me should fail with 401
        res_me_after = client.get('/api/auth/me')
        assert res_me_after.status_code == 401

    def test_login_invalid_password_returns_401(self, app, db_session):
        client = app.test_client()
        client.post('/api/auth/register', json={"email": "user2@zenix.io", "password": "Password123!"})

        res = client.post('/api/auth/login', json={"email": "user2@zenix.io", "password": "WrongPassword"})
        assert res.status_code == 401
        assert "Invalid email or password" in res.get_json()["error"]


class TestProtectedRoutesAndAuthorization:

    def test_unauthenticated_requests_rejected_with_401(self, app, db_session):
        client = app.test_client()

        routes = [
            ('/api/jobs', 'GET'),
            ('/api/jobs/upload', 'POST'),
            ('/api/telemetry/status', 'GET'),
            ('/api/telemetry/events', 'GET'),
            ('/api/vex', 'GET'),
        ]

        for url, method in routes:
            if method == 'GET':
                res = client.get(url)
            else:
                res = client.post(url)

            assert res.status_code == 401, f"Expected 401 for {method} {url}, got {res.status_code}"
            assert "Authentication required" in res.get_json()["error"]

    def test_user_cannot_access_other_users_job_status(self, app, db_session):
        """Analyst user receives 403 when requesting another user's job."""
        with app.app_context():
            u1 = User(email="u1@zenix.io", password_hash=hash_password("Pass123!"), role="analyst")
            u2 = User(email="u2@zenix.io", password_hash=hash_password("Pass123!"), role="analyst")
            db.session.add_all([u1, u2])
            db.session.commit()

            j1 = Job(id="job-user-1", user_id=u1.id, sbom_format="cyclonedx-json", sbom_sha256="123", status="done")
            db.session.add(j1)
            db.session.commit()

        client = app.test_client()

        # Login as u2
        client.post('/api/auth/login', json={"email": "u2@zenix.io", "password": "Pass123!"})

        # u2 attempts to access u1's job status -> 403 Forbidden
        jq = JobQueue(app, sync_mode=True)
        from api.jobs import init_jobs_api
        init_jobs_api(jq)

        res = client.get('/api/jobs/job-user-1/status')
        assert res.status_code == 403
        assert "Unauthorized" in res.get_json()["error"]

    def test_admin_can_access_any_user_job_status(self, app, db_session):
        """Admin user can access any job status."""
        with app.app_context():
            u1 = User(email="u1_sub@zenix.io", password_hash=hash_password("Pass123!"), role="analyst")
            admin = User(email="admin@zenix.io", password_hash=hash_password("Pass123!"), role="admin")
            db.session.add_all([u1, admin])
            db.session.commit()

            j1 = Job(id="job-user-sub", user_id=u1.id, sbom_format="cyclonedx-json", sbom_sha256="123", status="done")
            db.session.add(j1)
            db.session.commit()

        client = app.test_client()
        client.post('/api/auth/login', json={"email": "admin@zenix.io", "password": "Pass123!"})

        jq = JobQueue(app, sync_mode=True)
        from api.jobs import init_jobs_api
        init_jobs_api(jq)

        res = client.get('/api/jobs/job-user-sub/status')
        assert res.status_code == 200
        assert res.get_json()["job_id"] == "job-user-sub"
