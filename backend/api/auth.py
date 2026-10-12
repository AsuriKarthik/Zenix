"""
Authentication API Endpoints — Step 9 + Requirements 4 & 5 (Login Rate Limiting, CSRF, Cookie Security).

Endpoints:
  POST /api/auth/register — Register a new user (email, password, optional role).
  POST /api/auth/login — Authenticate credentials with IP rate-limiting (5 failed → 5 min lock).
  POST /api/auth/logout — Terminate current session.
  GET /api/auth/me — Return current authenticated user object (or 401).
  GET /api/auth/csrf-token — Get fresh CSRF token for state-changing requests.
"""

from __future__ import annotations

import hmac
import hashlib
import time
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from typing import Dict, List, Callable

import bcrypt
from flask import Blueprint, jsonify, request, session
from flask_login import LoginManager, login_user, logout_user, current_user, login_required

from config import Config
from db import db, User

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
log = logging.getLogger(__name__)

login_manager = LoginManager()


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 4: IP-based Login Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

# In-memory tracking: { ip_address: [timestamp_float, ...] }
_FAILED_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}


def _clean_old_attempts(ip: str, window_seconds: float = 900.0) -> List[float]:
    """Clean attempt timestamps older than window_seconds (default 15 mins)."""
    now = time.monotonic()
    attempts = [t for t in _FAILED_LOGIN_ATTEMPTS.get(ip, []) if now - t < window_seconds]
    _FAILED_LOGIN_ATTEMPTS[ip] = attempts
    return attempts


def is_ip_locked(ip: str) -> tuple[bool, int]:
    """
    Check if IP is locked out due to exceeding failed login threshold.

    Returns:
        (is_locked, seconds_remaining)
    """
    attempts = _clean_old_attempts(ip)
    max_attempts = getattr(Config, 'LOGIN_MAX_FAILED_ATTEMPTS', 5)
    lockout_seconds = getattr(Config, 'LOGIN_LOCKOUT_SECONDS', 300)

    if len(attempts) >= max_attempts:
        newest_attempt = max(attempts)
        elapsed = time.monotonic() - newest_attempt
        if elapsed < lockout_seconds:
            remaining = int(lockout_seconds - elapsed)
            return True, max(remaining, 1)

    return False, 0


def record_failed_attempt(ip: str) -> None:
    """Record a failed login attempt for an IP address."""
    attempts = _clean_old_attempts(ip)
    attempts.append(time.monotonic())
    _FAILED_LOGIN_ATTEMPTS[ip] = attempts


def clear_failed_attempts(ip: str) -> None:
    """Clear failed login attempt history for an IP address upon successful login."""
    _FAILED_LOGIN_ATTEMPTS.pop(ip, None)


# ─────────────────────────────────────────────────────────────────────────────
# Requirement 5: CSRF Double-Submit Token Protection
# ─────────────────────────────────────────────────────────────────────────────

def generate_csrf_token() -> str:
    """Generate or retrieve per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(f: Callable) -> Callable:
    """
    Decorator to validate CSRF token on state-changing requests (POST, PUT, DELETE).
    Validates X-CSRF-Token header against session['csrf_token'].
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            token_from_header = request.headers.get('X-CSRF-Token')
            token_from_session = session.get('csrf_token')

            if not token_from_header or not token_from_session or not hmac.compare_digest(token_from_header, token_from_session):
                log.warning("CSRF validation failed for IP %s on %s", request.remote_addr, request.path)
                return jsonify({"error": "CSRF validation failed. Missing or invalid X-CSRF-Token header."}), 403

        return f(*args, **kwargs)
    return decorated_function


# ─────────────────────────────────────────────────────────────────────────────
# Flask-Login configuration
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


@login_manager.unauthorized_handler
def unauthorized_response():
    return jsonify({"error": "Authentication required. Please log in."}), 401


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route('/csrf-token', methods=['GET'])
def get_csrf():
    """
    Get fresh CSRF token for authenticated session.
    Used by frontend clients in X-CSRF-Token header for state-changing requests.
    """
    token = generate_csrf_token()
    return jsonify({"csrf_token": token}), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register new user.
    Body JSON: {"email": "...", "password": "...", "role": "analyst"|"admin"}
    """
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role = data.get('role', 'analyst').strip().lower()

    if not email or '@' not in email:
        return jsonify({"error": "Valid email address is required."}), 400

    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    if role not in ('analyst', 'admin'):
        role = 'analyst'

    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": f"User with email '{email}' already exists."}), 409

    pwd_hash = hash_password(password)
    user = User(
        email=email,
        password_hash=pwd_hash,
        role=role,
        created_at=_utcnow(),
    )
    db.session.add(user)
    db.session.commit()

    log.info("Registered user %s (role: %s)", email, role)
    return jsonify({
        "message": "User registered successfully.",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user credentials and create session cookie.
    Enforces Requirement 4: Rate limits 5 failed attempts per IP address -> 5 minute lockout.
    """
    client_ip = request.remote_addr or '127.0.0.1'

    # Rate limiting check (Requirement 4)
    locked, remaining_secs = is_ip_locked(client_ip)
    if locked:
        log.warning("Blocked login attempt from locked IP %s (%d seconds remaining)", client_ip, remaining_secs)
        return jsonify({
            "error": f"Too many failed login attempts. Account temporarily locked for {remaining_secs} seconds."
        }), 429

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password_hash):
        record_failed_attempt(client_ip)
        attempts_count = len(_FAILED_LOGIN_ATTEMPTS.get(client_ip, []))
        log.warning("Invalid login attempt for %s from IP %s (attempt %d/5)", email, client_ip, attempts_count)
        return jsonify({
            "error": "Invalid email or password.",
            "attempts_remaining": max(0, 5 - attempts_count)
        }), 401

    # Successful login -> clear failed attempts & log in
    clear_failed_attempts(client_ip)
    login_user(user, remember=True)
    csrf_token = generate_csrf_token()

    log.info("Logged in user %s (id: %d) from IP %s", user.email, user.id, client_ip)

    return jsonify({
        "message": "Login successful.",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
        },
        "csrf_token": csrf_token,
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Terminate current user session."""
    user_email = current_user.email if current_user.is_authenticated else "unknown"
    logout_user()
    session.clear()
    log.info("Logged out user %s", user_email)
    return jsonify({"message": "Logout successful."}), 200


@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """
    Get current logged in user profile.
    Returns 401 if unauthenticated.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "Authentication required. Please log in."}), 401

    csrf_token = generate_csrf_token()
    return jsonify({
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        },
        "csrf_token": csrf_token,
    }), 200
