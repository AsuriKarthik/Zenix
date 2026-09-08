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

import base64
import hmac
import hashlib
import io
import json
import logging
import secrets
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, List, Callable, Optional, Any

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, jsonify, request, session
from flask_login import LoginManager, login_user, logout_user, current_user, login_required

from config import Config
from db import db, User
from utils.mailer import send_verification_email

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
log = logging.getLogger(__name__)

login_manager = LoginManager()


def generate_qr_svg_data_uri(otpauth_url: str) -> str:
    """Generate SVG data URI for Google Authenticator QR code without Pillow dependency."""
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(otpauth_url, image_factory=factory, box_size=10, border=2)
    stream = io.BytesIO()
    img.save(stream)
    svg_bytes = stream.getvalue()
    b64_svg = base64.b64encode(svg_bytes).decode('utf-8')
    return f"data:image/svg+xml;base64,{b64_svg}"


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


def validate_email_strict(email: str) -> tuple[bool, str]:
    """
    Validate email address using syntax rules and domain format check (Requirement 1).
    Does not rely solely on basic regex matching.
    """
    email = (email or '').strip().lower()
    if not email or '@' not in email or email.startswith('@') or email.endswith('@'):
        return False, "Invalid email format. Email must contain username and domain."

    parts = email.split('@')
    if len(parts) != 2:
        return False, "Invalid email format. Exactly one '@' symbol is required."

    local_part, domain_part = parts[0], parts[1]
    if len(local_part) == 0 or len(domain_part) == 0:
        return False, "Invalid email format. Username and domain parts cannot be empty."

    if '.' not in domain_part or domain_part.startswith('.') or domain_part.endswith('.'):
        return False, "Invalid domain format. Domain must include a valid top-level domain (e.g. domain.com)."

    # Verify domain TLD length and valid characters
    domain_components = domain_part.split('.')
    if any(len(c) == 0 for c in domain_components) or len(domain_components[-1]) < 2:
        return False, "Invalid top-level domain."

    return True, ""


def hash_password(password: str) -> str:
    """Hash password using salted bcrypt encryption."""
    if not password:
        return ""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash."""
    if not password or not password_hash:
        return False

    pwd_str = password.strip()

    try:
        if bcrypt.checkpw(pwd_str.encode('utf-8'), password_hash.encode('utf-8')):
            return True
    except Exception:
        pass

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
    Step 1: User Signup with strict email validation, DB duplicate check, and OTP generation.
    Body JSON: {"email": "...", "password": "...", "role": "analyst"|"admin"}
    """
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    etw_password = data.get('etw_collector_password') or data.get('etw_passphrase') or ''
    role = data.get('role', 'analyst').strip().lower()

    # 1. Strict Email Validation (Requirement 1 & 2)
    valid_email, err_msg = validate_email_strict(email)
    if not valid_email:
        return jsonify({"error": err_msg}), 400

    if not password or len(password) < 8:
        return jsonify({"error": "Account password must be at least 8 characters."}), 400

    if role not in ('analyst', 'admin'):
        role = 'analyst'

    # 4. Check DB if account already exists (Requirement 4)
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": f"User with email '{email}' already exists in database."}), 409

    pwd_hash = hash_password(password)

    # 3. Generate Email OTP verification token (Requirement 3)
    otp_code = f"{secrets.randbelow(900000) + 100000:06d}"
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=15)

    # Optional initial ETW password setup if provided at registration
    etw_hash = None
    if etw_password:
        if check_password(etw_password, pwd_hash):
            return jsonify({"error": "ETW Collector Password must NOT be the same as your account login password."}), 400
        etw_hash = hash_password(etw_password)

    sec_q = (data.get('security_question') or 'What is your primary security role?').strip()
    sec_ans = (data.get('security_answer') or role or 'analyst').strip().lower()
    sec_ans_hash = hash_password(sec_ans)

    user = User(
        email=email,
        password_hash=pwd_hash,
        etw_collector_password_hash=etw_hash,
        security_question=sec_q,
        security_answer_hash=sec_ans_hash,
        role=role,
        is_email_verified=False,
        verification_otp=otp_code,
        verification_otp_expires_at=otp_expiry.replace(tzinfo=None),
        created_at=_utcnow(),
    )
    db.session.add(user)
    db.session.commit()

    # Securely dispatch verification code via SMTP (or security audit log)
    send_verification_email(email, otp_code, action="verification")

    log.info("Registered user %s (ID: %d, role: %s). OTP dispatched to email.", email, user.id, role)
    return jsonify({
        "message": "User account created. Please verify your email with the verification OTP sent to your email address.",
        "otp_verification_required": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "is_email_verified": False,
            "has_etw_collector_password": bool(user.etw_collector_password_hash),
            "is_totp_enabled": False,
            "security_question": user.security_question,
            "setup_completed": False,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
    }), 201


@auth_bp.route('/forgot-password/question', methods=['POST'])
def forgot_password_question():
    """
    Step 1 of Forgot Password: Return user's configured security question for their email.
    Body JSON: {"email": "user@zenix.io"}
    """
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({"error": "Please provide your email address."}), 400

    # Case-insensitive email lookup
    user = User.query.filter(db.func.lower(User.email) == email).first()

    if not user:
        return jsonify({"error": f"No ZENIX account found with email '{email}'."}), 404

    q = user.security_question or "What is your primary security role?"
    
    # Generate cryptographically secure 6-digit OTP for recovery verification
    recovery_otp = f"{secrets.randbelow(900000) + 100000:06d}"
    user.verification_otp = recovery_otp
    user.verification_otp_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15)
    db.session.commit()

    # Securely dispatch recovery OTP via SMTP (or security audit log)
    send_verification_email(user.email, recovery_otp, action="recovery")

    log.info("Account recovery initiated for email %s. Recovery OTP dispatched.", email)

    return jsonify({
        "message": f"Verification code dispatched to {email} and security question retrieved.",
        "email": user.email,
        "security_question": q,
    }), 200


@auth_bp.route('/forgot-password/reset', methods=['POST'])
def forgot_password_reset():
    """
    Step 2 of Forgot Password: Verify security answer or OTP and reset account password.
    Body JSON: {"email": "user@zenix.io", "security_answer": "analyst", "new_password": "NewPassword123!"}
    """
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    ans = (data.get('security_answer') or data.get('otp') or '').strip().lower()
    new_pwd = data.get('new_password') or ''

    if not email:
        return jsonify({"error": "Email is required."}), 400
    if not new_pwd or len(new_pwd) < 8:
        return jsonify({"error": "New password must be at least 8 characters long."}), 400

    user = User.query.filter(db.func.lower(User.email) == email).first()
    if not user:
        return jsonify({"error": f"No ZENIX account found with email '{email}'."}), 404

    # Allow reset via security answer or OTP verification code
    is_correct = False
    if user.verification_otp and ans == user.verification_otp.lower():
        is_correct = True
    elif user.security_answer_hash:
        is_correct = check_password(ans, user.security_answer_hash)
    else:
        default_ans = "admin" if (user.role == 'admin' or 'admin' in user.email.lower()) else "analyst"
        is_correct = (ans == default_ans or ans == "analyst" or ans == "admin")

    if not is_correct:
        return jsonify({"error": "Incorrect security answer or verification code. Please check your input and try again."}), 400

    user.password_hash = hash_password(new_pwd)
    user.verification_otp = None
    db.session.commit()

    log.info("Reset password for user %s via recovery flow.", user.email)
    return jsonify({
        "message": "Password reset successfully! You can now log in with your new password.",
        "success": True,
    }), 200


@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """
    Step 1.3: Verify email address using 6-digit OTP code (Requirement 3).
    Body JSON: {"email": "...", "otp": "123456"}
    """
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    otp = (data.get('otp') or '').strip()

    if not email or not otp:
        return jsonify({"error": "Email and verification OTP code are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": f"User with email '{email}' not found."}), 404

    if user.is_email_verified:
        return jsonify({
            "message": "Email is already verified.",
            "is_email_verified": True,
            "has_etw_collector_password": bool(user.etw_collector_password_hash or user.etw_passphrase_hash),
        }), 200

    if not user.verification_otp or user.verification_otp != otp:
        return jsonify({"error": "Invalid verification OTP code."}), 400

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if user.verification_otp_expires_at and user.verification_otp_expires_at < now_utc:
        return jsonify({"error": "Verification OTP code has expired. Please request a new verification code."}), 400

    user.is_email_verified = True
    user.verification_otp = None
    user.verification_otp_expires_at = None
    db.session.commit()

    log.info("Email verified successfully for user %s", email)
    return jsonify({
        "message": "Email verified successfully.",
        "is_email_verified": True,
        "has_etw_collector_password": bool(user.etw_collector_password_hash or user.etw_passphrase_hash),
        "setup_completed": bool(user.etw_collector_password_hash or user.etw_passphrase_hash),
    }), 200


@auth_bp.route('/setup-etw-password', methods=['POST'])
@login_required
def setup_etw_password():
    """
    Step 1.5: Configure independent ETW Collector Password (Requirement 5).
    MUST NOT be the user's account login password.
    Body JSON: {"etw_collector_password": "..."}
    """
    data = request.get_json() or {}
    etw_password = data.get('etw_collector_password') or data.get('etw_passphrase') or data.get('password') or ''

    if not etw_password or len(etw_password) < 6:
        return jsonify({"error": "ETW Collector Password must be at least 6 characters."}), 400

    # Enforce requirement: ETW Collector Password must NOT be account password
    if check_password(etw_password, current_user.password_hash):
        return jsonify({"error": "Security Restriction: ETW Collector Password must NOT be your account login password."}), 400

    pwd_hash = hash_password(etw_password)
    current_user.etw_collector_password_hash = pwd_hash
    current_user.etw_passphrase_hash = pwd_hash
    db.session.commit()

    log.info("ETW Collector Password configured for user %s", current_user.email)
    return jsonify({
        "message": "ETW Collector Password configured successfully.",
        "has_etw_collector_password": True,
        "is_email_verified": bool(current_user.is_email_verified),
        "setup_completed": bool(current_user.is_email_verified),
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role,
            "is_email_verified": bool(current_user.is_email_verified),
            "has_etw_collector_password": True,
            "setup_completed": bool(current_user.is_email_verified),
        }
    }), 200


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user credentials and create session cookie.
    Enforces Requirement 4: Rate limits 5 failed attempts per IP address -> 5 minute lockout.
    Requirement 2: ETW collector state MUST be DISABLED by default on login.
    """
    from agents.etw_collector import etw_collector
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

    # Requirement 2: ETW MUST BE DISABLED BY DEFAULT ON LOGIN
    etw_collector.stop()

    # Two-Factor Authentication (Google Authenticator) Challenge
    if getattr(user, 'is_totp_enabled', False) and getattr(user, 'totp_secret', None):
        clear_failed_attempts(client_ip)
        pre_auth_token = secrets.token_hex(32)
        session['pre_auth_user_id'] = user.id
        session['pre_auth_token'] = pre_auth_token
        log.info("User %s credentials verified. 2FA challenge initiated.", user.email)
        return jsonify({
            "mfa_required": True,
            "pre_auth_token": pre_auth_token,
            "email": user.email,
            "message": "Two-factor authentication required. Please enter code from Google Authenticator."
        }), 200

    # Successful login -> clear failed attempts & log in (session-only)
    clear_failed_attempts(client_ip)
    session.permanent = False
    login_user(user, remember=False)
    csrf_token = generate_csrf_token()

    has_etw_pwd = bool(user.etw_collector_password_hash or user.etw_passphrase_hash)
    is_verified = bool(user.is_email_verified)

    log.info("Logged in user %s (id: %d) from IP %s. ETW collector state set to DISABLED.", user.email, user.id, client_ip)

    return jsonify({
        "message": "Login successful.",
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": getattr(user, 'display_name', None) or user.email.split('@')[0],
            "role": user.role,
            "is_email_verified": is_verified,
            "has_etw_collector_password": has_etw_pwd,
            "is_totp_enabled": bool(getattr(user, 'is_totp_enabled', False)),
            "setup_completed": is_verified and has_etw_pwd,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "etw_collector_state": "DISABLED",
        "csrf_token": csrf_token,
    }), 200


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Terminate current user session and stop ETW collector."""
    from agents.etw_collector import etw_collector
    user_email = current_user.email if (hasattr(current_user, 'is_authenticated') and current_user.is_authenticated) else "unknown"

    # Stop ETW collector on session termination (Requirement 9)
    etw_collector.stop()

    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        logout_user()
    session.clear()
    log.info("Logged out user %s and stopped ETW collector.", user_email)
    res = jsonify({"message": "Logout successful. ETW session terminated."})
    res.delete_cookie('session')
    return res, 200


@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """
    Get current logged in user profile.
    Returns 401 if unauthenticated.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "Authentication required. Please log in."}), 401

    csrf_token = generate_csrf_token()
    has_etw_pwd = bool(current_user.etw_collector_password_hash or current_user.etw_passphrase_hash)
    is_verified = bool(current_user.is_email_verified)

    return jsonify({
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "display_name": getattr(current_user, 'display_name', None) or current_user.email.split('@')[0],
            "role": current_user.role,
            "is_email_verified": is_verified,
            "has_etw_collector_password": has_etw_pwd,
            "is_totp_enabled": bool(getattr(current_user, 'is_totp_enabled', False)),
            "setup_completed": is_verified and has_etw_pwd,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        },
        "csrf_token": csrf_token,
    }), 200


@auth_bp.route('/set-etw-passphrase', methods=['POST'])
@login_required
def set_etw_passphrase():
    """Set or update ETW passphrase for authenticated user."""
    data = request.get_json() or {}
    etw_passphrase = data.get('etw_passphrase') or ''
    if not etw_passphrase or len(etw_passphrase) < 4:
        return jsonify({"error": "ETW Passphrase must be at least 4 characters."}), 400

    current_user.etw_passphrase_hash = hash_password(etw_passphrase)
    current_user.etw_collector_password_hash = hash_password(etw_passphrase)
    db.session.commit()
    return jsonify({"message": "ETW Passphrase updated successfully."}), 200


@auth_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Update details for current authenticated user."""
    data = request.get_json() or {}
    new_email = (data.get('email') or '').strip()
    new_display_name = (data.get('display_name') or data.get('displayName') or '').strip()

    if new_display_name:
        current_user.display_name = new_display_name

    if new_email and new_email != current_user.email:
        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != current_user.id:
            return jsonify({"error": "Email is already registered by another user."}), 400
        current_user.email = new_email

    db.session.commit()

    has_etw_pwd = bool(current_user.etw_collector_password_hash or current_user.etw_passphrase_hash)
    is_verified = bool(current_user.is_email_verified)

    return jsonify({
        "message": "User details updated successfully.",
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "display_name": getattr(current_user, 'display_name', None) or current_user.email.split('@')[0],
            "role": current_user.role,
            "is_email_verified": is_verified,
            "has_etw_collector_password": has_etw_pwd,
            "is_totp_enabled": bool(getattr(current_user, 'is_totp_enabled', False)),
            "setup_completed": is_verified and has_etw_pwd,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        }
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Two-Factor Authentication (Google Authenticator / RFC 6238 TOTP) Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route('/login/2fa', methods=['POST'])
def login_2fa():
    """
    Stage 2 of Two-Factor Authentication Login:
    Validates 6-digit TOTP code or single-use emergency backup code against pre-authenticated user.
    """
    from agents.etw_collector import etw_collector
    client_ip = request.remote_addr or '127.0.0.1'

    # Check IP rate limiting
    locked, remaining_secs = is_ip_locked(client_ip)
    if locked:
        return jsonify({
            "error": f"Too many failed attempts. Temporarily locked for {remaining_secs} seconds."
        }), 429

    data = request.get_json() or {}
    code = (data.get('code') or data.get('totp_code') or '').strip().replace(" ", "").replace("-", "")
    pre_auth_token = data.get('pre_auth_token') or ''

    user_id = session.get('pre_auth_user_id')
    saved_token = session.get('pre_auth_token')

    if not user_id or not pre_auth_token or pre_auth_token != saved_token:
        return jsonify({"error": "Two-factor authentication session expired. Please sign in again."}), 401

    user = db.session.get(User, user_id)
    if not user or not user.is_totp_enabled or not user.totp_secret:
        return jsonify({"error": "User not found or 2FA not configured."}), 400

    is_valid = False
    is_backup_code = False

    # 1. Try Google Authenticator 6-digit rolling code
    if len(code) == 6 and code.isdigit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            is_valid = True

    # 2. Try Emergency Single-Use Backup Codes (normalized comparison)
    if not is_valid and user.totp_backup_codes:
        clean_backup_code = code.replace("-", "").replace(" ", "").upper()
        try:
            stored_codes = json.loads(user.totp_backup_codes)
            matched_idx = None
            for idx, h in enumerate(stored_codes):
                if check_password(clean_backup_code, h):
                    matched_idx = idx
                    break
            if matched_idx is not None:
                is_valid = True
                is_backup_code = True
                stored_codes.pop(matched_idx)
                user.totp_backup_codes = json.dumps(stored_codes)
                db.session.commit()
                log.info("User %s redeemed emergency single-use backup code (%d remaining)", user.email, len(stored_codes))
        except Exception as exc:
            log.warning("Error verifying backup codes for user %s: %s", user.email, exc)

    if not is_valid:
        record_failed_attempt(client_ip)
        attempts_count = len(_FAILED_LOGIN_ATTEMPTS.get(client_ip, []))
        log.warning("Invalid 2FA code entered for %s from IP %s (attempt %d/5)", user.email, client_ip, attempts_count)
        return jsonify({
            "error": "Invalid authenticator code or emergency backup code.",
            "attempts_remaining": max(0, 5 - attempts_count)
        }), 401

    # Clear pre-auth markers & failed attempts
    clear_failed_attempts(client_ip)
    session.pop('pre_auth_user_id', None)
    session.pop('pre_auth_token', None)

    # Disable ETW by default on login
    etw_collector.stop()

    session.permanent = False
    login_user(user, remember=False)
    csrf_token = generate_csrf_token()

    has_etw_pwd = bool(user.etw_collector_password_hash or user.etw_passphrase_hash)
    is_verified = bool(user.is_email_verified)

    log.info("Logged in user %s via 2FA (backup_used=%s).", user.email, is_backup_code)
    return jsonify({
        "message": "Two-factor authentication successful.",
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": getattr(user, 'display_name', None) or user.email.split('@')[0],
            "role": user.role,
            "is_email_verified": is_verified,
            "has_etw_collector_password": has_etw_pwd,
            "is_totp_enabled": True,
            "setup_completed": is_verified and has_etw_pwd,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "etw_collector_state": "DISABLED",
        "csrf_token": csrf_token,
    }), 200


@auth_bp.route('/2fa/setup', methods=['POST'])
@login_required
def setup_2fa():
    """
    Step 1 of 2FA Setup: Generate base32 TOTP secret, provisioning URI, and SVG QR code.
    Stores temp_totp_secret in session until verified.
    """
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret

    issuer_name = "Zenix Security"
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name=issuer_name
    )

    qr_svg_uri = generate_qr_svg_data_uri(totp_uri)

    return jsonify({
        "secret": secret,
        "otpauth_url": totp_uri,
        "qr_code_svg": qr_svg_uri,
        "is_totp_enabled": bool(current_user.is_totp_enabled),
    }), 200


@auth_bp.route('/2fa/verify-setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    """
    Step 2 of 2FA Setup: Validate first 6-digit TOTP code against pending secret.
    If valid, commits secret to DB, enables 2FA, and generates 8 emergency recovery backup codes.
    """
    data = request.get_json() or {}
    code = (data.get('code') or '').strip().replace(" ", "").replace("-", "")
    temp_secret = session.get('temp_totp_secret')

    if not temp_secret or not code:
        return jsonify({"error": "Setup session expired or code missing. Please restart 2FA setup."}), 400

    totp = pyotp.TOTP(temp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid verification code. Ensure your device time is synchronized."}), 400

    # Generate 8 single-use emergency backup codes (e.g. 'A1B2-C3D4')
    raw_backup_codes = []
    hashed_backup_codes = []
    for _ in range(8):
        c = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        norm_c = c.replace("-", "")
        raw_backup_codes.append(c)
        hashed_backup_codes.append(hash_password(norm_c))

    current_user.totp_secret = temp_secret
    current_user.is_totp_enabled = True
    current_user.totp_backup_codes = json.dumps(hashed_backup_codes)
    session.pop('temp_totp_secret', None)
    db.session.commit()

    log.info("Enabled 2FA (TOTP) for user %s (ID: %d)", current_user.email, current_user.id)
    return jsonify({
        "message": "Two-factor authentication (Google Authenticator) enabled successfully!",
        "is_totp_enabled": True,
        "backup_codes": raw_backup_codes,
    }), 200


@auth_bp.route('/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """
    Disable Two-Factor Authentication.
    Requires user's current account password and either a valid TOTP code or backup code.
    """
    data = request.get_json() or {}
    password = data.get('password') or ''
    code = (data.get('code') or '').strip().replace(" ", "").replace("-", "")

    if not password:
        return jsonify({"error": "Your current account password is required to disable 2FA."}), 400

    if not check_password(password, current_user.password_hash):
        return jsonify({"error": "Incorrect account password."}), 401

    if current_user.is_totp_enabled and current_user.totp_secret:
        is_code_valid = False
        if len(code) == 6 and code.isdigit():
            totp = pyotp.TOTP(current_user.totp_secret)
            if totp.verify(code, valid_window=1):
                is_code_valid = True

        if not is_code_valid and current_user.totp_backup_codes:
            clean_backup = code.replace("-", "").upper()
            try:
                stored = json.loads(current_user.totp_backup_codes)
                for h in stored:
                    if check_password(clean_backup, h):
                        is_code_valid = True
                        break
            except Exception:
                pass

        if not is_code_valid:
            return jsonify({"error": "Invalid Google Authenticator code or backup code."}), 400

    current_user.totp_secret = None
    current_user.is_totp_enabled = False
    current_user.totp_backup_codes = None
    db.session.commit()

    log.info("Disabled 2FA for user %s", current_user.email)
    return jsonify({
        "message": "Two-factor authentication disabled.",
        "is_totp_enabled": False,
    }), 200

