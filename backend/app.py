"""
Zenix Flask Application.

Main entry point for Zenix backend server.
App initializes database tables, session login manager, background job queue,
and registers API blueprints (auth, jobs, telemetry, vex).
"""

from __future__ import annotations
import os

from flask import Flask
from flask_cors import CORS

from config import Config
from db import init_db
from jobs.queue import JobQueue
from api.auth import auth_bp, login_manager
from api.jobs import jobs_bp, init_jobs_api
from api.telemetry import telemetry_bp
from api.vex import vex_bp

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for frontend with credentials (session cookies)
CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}}, supports_credentials=True)

# Initialize database tables
init_db(app)

# Initialize Flask-Login manager
login_manager.init_app(app)

# Initialize background JobQueue
job_queue = JobQueue(app, max_workers=2, stale_timeout_seconds=300)
init_jobs_api(job_queue)

# Register API blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(jobs_bp)
app.register_blueprint(telemetry_bp)
app.register_blueprint(vex_bp)


@app.after_request
def apply_security_headers(response):
    """Apply standard security headers to every response (Requirement 5)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='127.0.0.1', port=5000, debug=debug_mode)
