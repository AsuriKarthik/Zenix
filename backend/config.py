"""
Zenix configuration.

All tuneable values come from environment variables.
No secrets, URLs, or constants are hardcoded in application code.

Usage:
    from config import Config
    app.config.from_object(Config)
"""

from __future__ import annotations

import logging
import os
import secrets

from dotenv import load_dotenv

# Load .env from the directory this file lives in
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

log = logging.getLogger(__name__)


class Config:
    # ── Core ──────────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get('SECRET_KEY', 'zenix_permanent_session_secret_key_839210948')


    # ── Database ──────────────────────────────────────────────────────────────
    _default_db = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'zenix.db')}"
    SQLALCHEMY_DATABASE_URI: str = os.environ.get('DATABASE_URL', _default_db)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ── Session & Cookie Security (Requirement 5) ─────────────────────────────
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    SESSION_COOKIE_SECURE: bool = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SAMESITE: str = 'Lax'
    REMEMBER_COOKIE_SECURE: bool = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_DURATION: int = 30 * 86400  # 30 days persistence
    PERMANENT_SESSION_LIFETIME: int = 30 * 86400  # 30 days persistence


    # ── Auth & Rate Limiting (Requirement 4) ──────────────────────────────────
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 300  # 5 minutes lockout after 5 failed attempts

    # ── Job Queue & Stale Timeout Settings ────────────────────────────────────
    JOB_STALE_TIMEOUT_SECONDS: int = int(os.environ.get('JOB_STALE_TIMEOUT_SECONDS', 1800))

    # ── Upload Limits & Content Size (Requirement 6) ──────────────────────────

    MAX_CONTENT_LENGTH: int = 10 * 1024 * 1024   # 10 MB maximum upload payload
    MAX_SBOM_SIZE_BYTES: int = 10 * 1024 * 1024   # 10 MB
    ALLOWED_UPLOAD_EXTENSIONS: set = {'.json'}
    UPLOAD_FOLDER: str = os.environ.get(
        'UPLOAD_FOLDER',
        os.path.join(os.path.dirname(__file__), 'uploads')
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list = os.environ.get('CORS_ORIGINS', 'http://localhost:5173').split(',')

    # ── NVD API ───────────────────────────────────────────────────────────────
    NVD_API_KEY: str = os.environ.get('NVD_API_KEY', '')
    NVD_API_BASE: str = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    NVD_RATE_LIMIT_DELAY: float = 0.65 if NVD_API_KEY else 7.0
    NVD_CACHE_HOURS: int = 24

    # ── EPSS API (FIRST.org) ──────────────────────────────────────────────────
    EPSS_API_BASE: str = 'https://api.first.org/data/v1/epss'
    EPSS_CACHE_HOURS: int = 24
    EPSS_RATE_LIMIT_DELAY: float = 1.0

    # ── CISA KEV ──────────────────────────────────────────────────────────────
    CISA_KEV_URL: str = (
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    )
    CISA_KEV_CACHE_HOURS: int = 6

    # ── OSV.dev ───────────────────────────────────────────────────────────────
    OSV_API_BASE: str = 'https://api.osv.dev/v1'
    OSV_CACHE_HOURS: int = 6
    OSV_RATE_LIMIT_DELAY: float = 0.5

    # ── Asymmetric VEX Signing (Requirement 3) ────────────────────────────────
    VEX_PRIVATE_KEY_PEM: str = os.environ.get('VEX_PRIVATE_KEY_PEM', '')

    # ── Shodan Threat Intelligence ────────────────────────────────────────────
    SHODAN_API_KEY: str = os.environ.get('SHODAN_API_KEY', '')
    SHODAN_CACHE_HOURS: int = 12

    # ── VirusTotal Threat Intelligence ────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = os.environ.get('VIRUSTOTAL_API_KEY', '')
    VIRUSTOTAL_CACHE_HOURS: int = 12

    # ── SMTP Email Dispatch (OTP / 2FA) ───────────────────────────────────────
    SMTP_SERVER: str = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT: int = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME: str = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD: str = os.environ.get('SMTP_PASSWORD', '')
    SMTP_FROM: str = os.environ.get('SMTP_FROM', 'no-reply@zenix.security')
