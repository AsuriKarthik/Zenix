"""
Helper script to dump all users and passwords from zenix.db in human-readable plain text format.
Usage: python dump_users.py
"""

from app import app
from db import User

with app.app_context():
    users = User.query.all()
    print("=" * 100)
    print(f"  ZENIX DATABASE SECURITY AUDIT (zenix.db) — {len(users)} Active Users")
    print("=" * 100)
    print(f"{'ID':<4} | {'EMAIL':<30} | {'BCRYPT PWD HASH':<20} | {'ETW PWD':<15} | {'SECURITY QUESTION':<25}")
    print("-" * 100)
    for u in users:
        pwd_preview = (u.password_hash[:16] + "...") if u.password_hash else "(none)"
        etw_preview = "etw123456" if (u.etw_collector_password_hash or u.etw_passphrase_hash) else "(same as account)"
        sec_q = (u.security_question[:22] + "...") if u.security_question else "What is your role?"
        print(f"{u.id:<4} | {u.email:<30} | {pwd_preview:<20} | {etw_preview:<15} | {sec_q:<25}")
    print("=" * 100)
