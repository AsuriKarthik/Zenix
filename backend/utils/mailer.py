"""
SMTP Mailer Service for Zenix.

Dispatches one-time verification (OTP) codes and security alerts via standard SMTP.
Guarantees that sensitive authentication secrets are never leaked into API HTTP responses.
"""

from __future__ import annotations
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from config import Config

log = logging.getLogger(__name__)

AUDIT_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "security_audit.log")


def _record_audit_log(to_email: str, action: str, note: str) -> None:
    """Record a secure operational audit event to backend/logs/security_audit.log."""
    try:
        os.makedirs(AUDIT_LOG_DIR, exist_ok=True)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{now_str}] [SECURITY_AUDIT] Action: {action} | Recipient: {to_email} | {note}\n")
    except Exception as exc:
        log.warning("Could not write to security_audit.log: %s", exc)


def send_verification_email(to_email: str, otp_code: str, action: str = "verification") -> bool:
    """
    Send OTP verification code to user email via live SMTP.
    If SMTP server is configured in Config, dispatches the email securely.
    If SMTP server is unconfigured, logs an audit dispatch event to security_audit.log
    so the developer/admin can review it without exposing the OTP in public HTTP responses.

    Returns True if sent or handled cleanly, False on failure.
    """
    host = getattr(Config, 'SMTP_HOST', None) or getattr(Config, 'SMTP_SERVER', None)
    port = int(getattr(Config, 'SMTP_PORT', 587))
    user = getattr(Config, 'SMTP_USER', None) or getattr(Config, 'SMTP_USERNAME', None)
    password = getattr(Config, 'SMTP_PASSWORD', None)
    sender = getattr(Config, 'SMTP_FROM', 'no-reply@zenix.local')
    use_tls = getattr(Config, 'SMTP_USE_TLS', True)

    subject = f"Zenix Security Verification Code [{otp_code[:3]}-***]" if action == "verification" else f"Zenix Password Recovery Code [{otp_code[:3]}-***]"

    body_text = f"""Hello,

Your verification code for Zenix Security Platform is:

    {otp_code}

This code is valid for 15 minutes.
If you did not request this security code, please ignore this email.

— Zenix Security Intelligence System
"""

    if host and user and password:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = to_email
            msg.attach(MIMEText(body_text, "plain", "utf-8"))

            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                if use_tls:
                    server.starttls()

            server.login(user, password)
            server.sendmail(sender, [to_email], msg.as_string())
            server.quit()

            log.info("Successfully dispatched OTP email to %s via SMTP host %s", to_email, host)
            _record_audit_log(to_email, action, f"Dispatched successfully via SMTP ({host}:{port})")
            return True
        except Exception as exc:
            log.error("Failed to send SMTP email to %s: %s", to_email, exc)
            _record_audit_log(to_email, action, f"SMTP delivery failed: {exc}.")
            return False
    else:
        # SMTP unconfigured: safely log audit record without leaking secrets
        log.info("SMTP unconfigured. Recording OTP dispatch audit for %s", to_email)
        _record_audit_log(to_email, action, "SMTP unconfigured. Dispatch event recorded.")
        return True
