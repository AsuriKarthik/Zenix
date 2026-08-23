"""
pytest conftest — shared fixtures for the Zenix backend test suite.

All fixtures use in-memory SQLite so tests are isolated and require no
external services or file-system state.

Test HTTP calls (OSV, NVD, EPSS, KEV) are mocked via the `responses` library
in individual test modules — no real network calls are made during tests.
"""

import os
import pathlib
import pytest

from flask import Flask

# Import db from our new module, not the old app
from db import db as _db
from config import Config


FIXTURE_DIR = pathlib.Path(__file__).parent / 'fixtures'


# ─────────────────────────────────────────────────────────────────────────────
# Flask app + DB fixtures
# ─────────────────────────────────────────────────────────────────────────────

from config import Config
from api.auth import auth_bp, login_manager
from api.jobs import jobs_bp
from api.telemetry import telemetry_bp
from api.vex import vex_bp

@pytest.fixture(scope='session')
def app():
    """
    A test Flask application with an in-memory SQLite database.
    """
    flask_app = Flask(__name__, instance_relative_config=False)
    flask_app.config.from_object(Config)
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY='test-secret-do-not-use-in-production',
    )
    login_manager.init_app(flask_app)
    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(jobs_bp)
    flask_app.register_blueprint(telemetry_bp)
    flask_app.register_blueprint(vex_bp)

    @flask_app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    _db.init_app(flask_app)
    return flask_app


@pytest.fixture()
def db_session(app):
    """
    A clean database session for one test.

    Creates all tables before the test, rolls back (and drops) after.
    Each test starts with a completely empty schema.
    """
    with app.app_context():
        _db.create_all()
        yield _db.session
        _db.session.remove()
        _db.drop_all()
        _db.engine.dispose()


@pytest.fixture()
def app_ctx(app):
    """Push an application context for tests that need it but don't use the DB."""
    with app.app_context():
        yield


# ─────────────────────────────────────────────────────────────────────────────
# SBOM fixture data
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_sbom_bytes():
    """
    Raw bytes of the CycloneDX JSON test fixture.
    DEV FIXTURE — not used in production pipeline.
    """
    path = FIXTURE_DIR / 'sample_sbom_cyclonedx.json'
    return path.read_bytes()


@pytest.fixture()
def minimal_sbom_bytes():
    """Minimal valid CycloneDX 1.4 JSON with a single component."""
    content = """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "example-lib",
      "version": "1.0.0",
      "purl": "pkg:npm/example-lib@1.0.0"
    }
  ]
}"""
    return content.encode('utf-8')
