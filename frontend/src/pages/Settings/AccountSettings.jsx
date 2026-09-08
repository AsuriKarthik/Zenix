/**
 * Account Settings Page — Zenix Security Platform
 *
 * Full-width layout matching native Zenix System Status design:
 *   - Left Box: User Account Details (Interactive inline editing for Display Handle + instant DB update)
 *   - Right Box: Security Telemetry (Fills empty side space with matching box design & session integrity)
 *   - Lower Section: Two-Factor Authentication (RFC 6238 TOTP / Google Authenticator) setup, backup codes & disablement
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../../hooks/useAuth';
import useAuthStore from '../../store/authStore';
import { formatTimestamp } from '../../utils/formatters';
import {
  User, CheckCircle2, Edit3, Save, X, AlertTriangle, ShieldCheck,
  Smartphone, QrCode, Copy, Check, Download, Shield, KeyRound, Lock, ShieldAlert
} from 'lucide-react';
import PulseIndicator from '../../components/ui/PulseIndicator';
import { updateProfile, setup2FA, verify2FASetup, disable2FA } from '../../api/auth';

export default function AccountSettings() {
  const { user } = useAuth();
  const setUser = useAuthStore((state) => state.setUser);

  const [isEditing, setIsEditing] = useState(false);
  const [displayName, setDisplayName] = useState(user?.display_name || (user?.email ? user.email.split('@')[0] : ''));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  // ── Two-Factor Authentication State ───────────────────────────────
  const isTotpActive = Boolean(user?.is_totp_enabled);

  // Setup Modal State
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [setupStep, setSetupStep] = useState(1); // 1 = QR & Code, 2 = Backup Codes
  const [setupLoading, setSetupLoading] = useState(false);
  const [setupError, setSetupError] = useState(null);
  const [totpSecret, setTotpSecret] = useState('');
  const [qrCodeSvg, setQrCodeSvg] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  // Disable Modal State
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disableLoading, setDisableLoading] = useState(false);
  const [disableError, setDisableError] = useState(null);
  const [disableSuccess, setDisableSuccess] = useState(null);

  // Sync state ONLY when NOT currently editing so background polling NEVER interrupts typing
  useEffect(() => {
    if (user && !isEditing) {
      setDisplayName(user.display_name || (user.email ? user.email.split('@')[0] : ''));
    }
  }, [user?.id, user?.display_name, isEditing]);

  const handleStartEditing = () => {
    setDisplayName(user?.display_name || (user?.email ? user.email.split('@')[0] : ''));
    setError(null);
    setIsEditing(true);
  };

  const handleUpdate = async (e) => {
    if (e) e.preventDefault();
    const cleanName = displayName.trim();
    if (!cleanName) {
      setError('Display Name cannot be empty.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const res = await updateProfile({
        display_name: cleanName,
      });
      if (res.user) {
        setUser({ ...user, ...res.user, display_name: cleanName });
      } else {
        setUser({ ...user, display_name: cleanName });
      }
      setSaved(true);
      setIsEditing(false); // Lock back into read-only box state
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update Display Name.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    setDisplayName(user?.display_name || (user?.email ? user.email.split('@')[0] : ''));
    setError(null);
    setIsEditing(false);
  };

  // ── 2FA Setup Flow Handlers ───────────────────────────────────────
  const handleOpenSetup = async () => {
    setShowSetupModal(true);
    setSetupStep(1);
    setSetupLoading(true);
    setSetupError(null);
    setVerificationCode('');
    setBackupCodes([]);
    setCopiedSecret(false);
    setCopiedCodes(false);

    try {
      const data = await setup2FA();
      setTotpSecret(data.secret || '');
      setQrCodeSvg(data.qr_code_svg || '');
    } catch (err) {
      setSetupError(err.response?.data?.error || 'Failed to initialize 2FA setup. Please try again.');
    } finally {
      setSetupLoading(false);
    }
  };

  const handleVerifySetup = async (e) => {
    e.preventDefault();
    const cleanCode = verificationCode.trim().replace(/\s+/g, '').replace(/-/g, '');
    if (!cleanCode) {
      setSetupError('Please enter the 6-digit code from your authenticator app.');
      return;
    }

    setSetupLoading(true);
    setSetupError(null);

    try {
      const data = await verify2FASetup(cleanCode);
      if (data.backup_codes) {
        setBackupCodes(data.backup_codes);
        setSetupStep(2);
      }
      if (user) {
        setUser({ ...user, is_totp_enabled: true });
      }
    } catch (err) {
      setSetupError(err.response?.data?.error || 'Invalid verification code. Ensure your device time is synchronized.');
    } finally {
      setSetupLoading(false);
    }
  };

  const handleCopySecret = () => {
    if (!totpSecret) return;
    navigator.clipboard.writeText(totpSecret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2500);
  };

  const handleCopyBackupCodes = () => {
    if (!backupCodes.length) return;
    navigator.clipboard.writeText(backupCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2500);
  };

  const handleDownloadBackupCodes = () => {
    if (!backupCodes.length) return;
    const text = `ZENIX SECURITY PLATFORM — EMERGENCY 2FA RECOVERY CODES
Generated: ${new Date().toISOString()}
Account: ${user?.email || 'analyst'}

CRITICAL SECURITY NOTICE:
Each code below can be used EXACTLY ONCE if you lose access to your primary authenticator device.
Store this file in an encrypted vault or offline password manager.

${backupCodes.map((c, i) => `[${i + 1}] ${c}`).join('\n')}
`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zenix-recovery-codes-${(user?.email || 'analyst').split('@')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleFinishSetup = () => {
    setShowSetupModal(false);
    setVerificationCode('');
    setBackupCodes([]);
  };

  // ── 2FA Disablement Handlers ─────────────────────────────────────
  const handleOpenDisable = () => {
    setShowDisableModal(true);
    setDisablePassword('');
    setDisableCode('');
    setDisableError(null);
    setDisableSuccess(null);
  };

  const handleConfirmDisable = async (e) => {
    e.preventDefault();
    if (!disablePassword) {
      setDisableError('Current account password is required to disable 2FA.');
      return;
    }

    setDisableLoading(true);
    setDisableError(null);

    try {
      await disable2FA(disablePassword, disableCode.trim());
      setDisableSuccess('Two-Factor Authentication disabled successfully.');
      if (user) {
        setUser({ ...user, is_totp_enabled: false });
      }
      setTimeout(() => {
        setShowDisableModal(false);
        setDisablePassword('');
        setDisableCode('');
        setDisableSuccess(null);
      }, 1500);
    } catch (err) {
      setDisableError(err.response?.data?.error || 'Failed to disable 2FA. Check your password and verification code.');
    } finally {
      setDisableLoading(false);
    }
  };

  const accountEmail = user?.email || '—';
  const accountDisplayName = user?.display_name || displayName || (user?.email ? user.email.split('@')[0] : '—');
  const userRole = user?.role ? user.role.toUpperCase() : 'ANALYST';
  const userId = user?.id ? String(user.id) : '—';
  const sessionTime = user?.created_at ? formatTimestamp(user.created_at) : 'Active Session';

  return (
    <div>
      <div className="stat-grid-2 mb-6">
        
        {/* Left Box: User Account Details */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <div style={{
                width: 36, height: 36,
                background: 'var(--bg-surface-2)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <User size={16} style={{ color: 'var(--color-verified)' }} />
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>User Account Details</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  IDENTITY MATRIX & SESSION CREDS
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <PulseIndicator variant="verified" />
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: 1,
                color: 'var(--color-verified)',
              }}>
                AUTHENTICATED SESSION
              </span>
            </div>
          </div>

          <form onSubmit={handleUpdate}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 'var(--space-3)',
              marginBottom: 'var(--space-4)',
            }}>
              {/* Account Email (Read-Only) */}
              <div style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  ACCOUNT EMAIL
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                  {accountEmail}
                </div>
              </div>

              {/* Display Handle — Directly Clickable & Editable */}
              <div
                onClick={() => { if (!isEditing) handleStartEditing(); }}
                style={{
                  padding: 'var(--space-2) var(--space-3)',
                  background: isEditing ? 'rgba(56, 189, 248, 0.1)' : 'var(--bg-surface-2)',
                  borderRadius: 'var(--radius-sm)',
                  border: isEditing ? '1px solid var(--color-accent)' : '1px solid rgba(255, 255, 255, 0.1)',
                  cursor: isEditing ? 'default' : 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: isEditing ? 'var(--color-accent)' : 'var(--text-muted)' }}>
                    DISPLAY HANDLE {isEditing ? '(EDITING)' : '(CLICK TO EDIT)'}
                  </div>
                  {!isEditing && <Edit3 size={11} style={{ color: 'var(--color-accent)' }} />}
                </div>
                {isEditing ? (
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    autoFocus
                    required
                    placeholder="Enter your display name..."
                    style={{
                      width: '100%',
                      fontSize: 13,
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      padding: '6px 10px',
                      color: '#FFFFFF',
                      background: 'rgba(0, 0, 0, 0.6)',
                      border: '1px solid var(--color-accent)',
                      borderRadius: 4,
                      outline: 'none',
                      boxShadow: '0 0 8px rgba(56, 189, 248, 0.3)',
                    }}
                  />
                ) : (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {accountDisplayName}
                  </div>
                )}
              </div>

              {/* Role & Permissions */}
              <div style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  ROLE & PERMISSIONS
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {userRole}
                </div>
              </div>

              {/* User ID */}
              <div style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  USER ID
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {userId}
                </div>
              </div>

              {/* Session Created */}
              <div style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  SESSION CREATED
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {sessionTime}
                </div>
              </div>

              {/* Session Status */}
              <div style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  SESSION STATUS
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                  Active & Encrypted
                </div>
              </div>
            </div>

            {error && (
              <div className="alert alert-error mb-4">
                <AlertTriangle size={14} />
                {error}
              </div>
            )}

            {saved && (
              <div className="alert alert-success mb-4">
                <CheckCircle2 size={14} style={{ color: 'var(--color-verified)' }} />
                Display Name updated successfully.
              </div>
            )}

            {/* Action Buttons: Shown only when editing */}
            {isEditing && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-start', gap: 'var(--space-2)' }}>
                <button type="submit" className="btn btn-primary btn-sm" disabled={submitting} style={{ gap: 6 }}>
                  <Save size={13} /> {submitting ? 'Updating…' : 'Update Display Name'}
                </button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={handleCancel} disabled={submitting} style={{ gap: 6 }}>
                  <X size={13} /> Cancel
                </button>
              </div>
            )}
          </form>
        </div>

        {/* Right Box: Security Telemetry (Fills empty space with matching box design) */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <div style={{
                width: 36, height: 36,
                background: 'var(--bg-surface-2)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <ShieldCheck size={16} style={{ color: 'var(--color-accent)' }} />
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Security Telemetry</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  CRYPTOGRAPHIC & SESSION INTEGRITY
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <PulseIndicator variant="accent" />
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: 1,
                color: 'var(--color-accent)',
              }}>
                ENCRYPTED TIER
              </span>
            </div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 'var(--space-3)',
            marginBottom: 'var(--space-4)',
          }}>
            {/* Authentication Method */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                AUTHENTICATION TYPE
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                Bcrypt Salted + TOTP RFC 6238
              </div>
            </div>

            {/* Session Encryption */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                SESSION CIPHER
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                AES-256-GCM / TLS 1.3
              </div>
            </div>

            {/* Credential Integrity */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                VEX SIGNING KEY
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                ECDSA P-256 Verified
              </div>
            </div>

            {/* ETW Profiler Privilege */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                PROFILING PRIVILEGE
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                ETW Kernel Level 2
              </div>
            </div>

            {/* Isolation Policy */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                DATA ISOLATION
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                Tenant Strict Isolated
              </div>
            </div>

            {/* Client Connection */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                CONNECTION ORIGIN
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                127.0.0.1 (Authenticated)
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            <CheckCircle2 size={13} style={{ color: 'var(--color-verified)' }} /> All identity & cryptographic credentials verified
          </div>
        </div>

      </div>

      {/* ── LOWER SECTION: Two-Factor Authentication (RFC 6238 TOTP) Card ──────── */}
      <div className="card mb-6" style={{ position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{
              width: 40, height: 40,
              background: isTotpActive ? 'rgba(34, 197, 94, 0.12)' : 'rgba(245, 158, 11, 0.12)',
              border: `1px solid ${isTotpActive ? 'rgba(34, 197, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
              borderRadius: 'var(--radius-md)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Smartphone size={20} style={{ color: isTotpActive ? 'var(--color-verified)' : 'var(--color-warning)' }} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Two-Factor Authentication (2FA)
                </span>
                <span style={{
                  fontSize: 10,
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: isTotpActive ? 'rgba(34, 197, 94, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                  color: isTotpActive ? 'var(--color-verified)' : 'var(--color-warning)',
                  border: `1px solid ${isTotpActive ? 'rgba(34, 197, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                  fontWeight: 600,
                  letterSpacing: 0.5,
                }}>
                  {isTotpActive ? 'ACTIVE' : 'DISABLED'}
                </span>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <PulseIndicator variant={isTotpActive ? 'verified' : 'warning'} />
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: 1,
              color: isTotpActive ? 'var(--color-verified)' : 'var(--color-warning)',
            }}>
              {isTotpActive ? 'ENFORCED' : 'INACTIVE'}
            </span>
          </div>
        </div>

        {/* Content Box */}
        {isTotpActive ? (
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: 'var(--space-3) var(--space-4)',
            background: 'var(--bg-surface-2)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid rgba(34, 197, 94, 0.2)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <ShieldCheck size={18} style={{ color: 'var(--color-verified)' }} />
              <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                Google Authenticator is active for this account.
              </span>
            </div>

            <button
              type="button"
              onClick={handleOpenDisable}
              className="btn btn-ghost"
              style={{
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#F87171',
                background: 'rgba(239, 68, 68, 0.08)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12,
                padding: '6px 14px',
              }}
            >
              <Lock size={13} /> Disable 2FA
            </button>
          </div>
        ) : (
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: 'var(--space-3) var(--space-4)',
            background: 'var(--bg-surface-2)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Smartphone size={18} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                Protect your account with Google Authenticator.
              </span>
            </div>

            <button
              type="button"
              id="enable-2fa-btn"
              onClick={handleOpenSetup}
              className="btn btn-primary"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                fontSize: 12,
                padding: '8px 16px',
                fontWeight: 600,
              }}
            >
              <Smartphone size={14} /> Enable 2FA
            </button>
          </div>
        )}
      </div>

      {/* ── 2FA SETUP MODAL ────────────────────────────────────────────── */}
      <AnimatePresence>
        {showSetupModal && (
          <div className="modal-backdrop" style={{
            position: 'fixed', inset: 0, zIndex: 9999,
            background: 'rgba(0, 0, 0, 0.85)', backdropFilter: 'blur(8px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
          }}>
            <motion.div
              className="card"
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ duration: 0.2 }}
              style={{
                width: '100%',
                maxWidth: 520,
                background: '#14141A',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: 16,
                padding: 24,
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8)',
              }}
            >
              {/* Modal Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 32, height: 32,
                    borderRadius: 8,
                    background: 'rgba(56, 189, 248, 0.15)',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center'
                  }}>
                    {setupStep === 1 ? <QrCode size={16} color="#38BDF8" /> : <KeyRound size={16} color="#22C55E" />}
                  </div>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F5F5' }}>
                      {setupStep === 1 ? 'Pair Google Authenticator' : 'Emergency Backup Codes'}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#94A3B8' }}>
                      {setupStep === 1 ? 'STEP 1 OF 2: DEVICE ENROLLMENT' : 'STEP 2 OF 2: RECOVERY VAULT'}
                    </div>
                  </div>
                </div>
                {setupStep === 1 && (
                  <button
                    type="button"
                    onClick={() => setShowSetupModal(false)}
                    style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: 18 }}
                  >
                    ✕
                  </button>
                )}
              </div>

              {/* STEP 1: Scan QR Code & Enter 6-digit Verification Code */}
              {setupStep === 1 && (
                <div>
                  <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 16, lineHeight: 1.5 }}>
                    Open your authenticator app (<strong style={{ color: '#F5F5F5' }}>Google Authenticator</strong>, <strong style={{ color: '#F5F5F5' }}>Authy</strong>, or <strong style={{ color: '#F5F5F5' }}>1Password</strong>) and scan the QR code below.
                  </div>

                  {setupLoading && !qrCodeSvg ? (
                    <div style={{ textAlign: 'center', padding: '30px 0', color: '#94A3B8', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      GENERATING CRYPTOGRAPHIC PAIRING KEY…
                    </div>
                  ) : (
                    <>
                      {/* QR Code Container */}
                      <div style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        background: '#FFFFFF',
                        borderRadius: 12,
                        padding: 16,
                        maxWidth: 210,
                        margin: '0 auto 16px auto',
                        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
                      }}>
                        {qrCodeSvg && (
                          <img
                            src={qrCodeSvg}
                            alt="Google Authenticator QR Code"
                            style={{ width: 178, height: 178, display: 'block' }}
                          />
                        )}
                      </div>

                      {/* Manual Secret Key */}
                      <div style={{
                        background: 'rgba(0, 0, 0, 0.4)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: 8,
                        padding: '10px 12px',
                        marginBottom: 18,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                      }}>
                        <div style={{ overflow: 'hidden' }}>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: 1 }}>
                            MANUAL CONFIGURATION KEY
                          </div>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#DAFC6F', fontWeight: 700, letterSpacing: 1.5, wordBreak: 'break-all', marginTop: 2 }}>
                            {totpSecret || '—'}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={handleCopySecret}
                          className="btn btn-ghost btn-sm"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 4,
                            fontSize: 11,
                            padding: '4px 8px',
                            background: 'rgba(255, 255, 255, 0.06)',
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                            color: copiedSecret ? '#4ADE80' : '#F5F5F5',
                            flexShrink: 0,
                          }}
                        >
                          {copiedSecret ? <Check size={12} /> : <Copy size={12} />}
                          {copiedSecret ? 'Copied' : 'Copy'}
                        </button>
                      </div>

                      {/* Verification Code Input Form */}
                      <form onSubmit={handleVerifySetup}>
                        <div className="input-group mb-4">
                          <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>
                            Enter 6-Digit Code from Authenticator
                          </label>
                          <input
                            id="totp-setup-code-input"
                            className="input input-mono"
                            type="text"
                            placeholder="000000"
                            value={verificationCode}
                            onChange={(e) => setVerificationCode(e.target.value)}
                            maxLength={8}
                            required
                            autoFocus
                            autoComplete="one-time-code"
                            disabled={setupLoading}
                            style={{
                              textAlign: 'center',
                              fontSize: 20,
                              letterSpacing: 6,
                              fontWeight: 700,
                              color: '#DAFC6F',
                              background: 'rgba(0, 0, 0, 0.5)',
                              border: '1px solid rgba(218, 252, 111, 0.4)',
                              borderRadius: 8,
                              padding: '10px 14px',
                            }}
                          />
                        </div>

                        {setupError && (
                          <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>
                            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                            <div>{setupError}</div>
                          </div>
                        )}

                        <div style={{ display: 'flex', gap: 10 }}>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            onClick={() => setShowSetupModal(false)}
                            style={{ flex: 1 }}
                            disabled={setupLoading}
                          >
                            Cancel
                          </button>
                          <button
                            type="submit"
                            id="verify-2fa-setup-btn"
                            className="btn btn-primary"
                            style={{ flex: 2 }}
                            disabled={setupLoading || !verificationCode.trim()}
                          >
                            {setupLoading ? 'Verifying Code…' : 'Activate 2FA'}
                          </button>
                        </div>
                      </form>
                    </>
                  )}
                </div>
              )}

              {/* STEP 2: Emergency Single-Use Backup Codes Display */}
              {setupStep === 2 && (
                <div>
                  <div style={{
                    padding: 12,
                    background: 'rgba(34, 197, 94, 0.12)',
                    border: '1px solid rgba(34, 197, 94, 0.3)',
                    borderRadius: 8,
                    marginBottom: 16,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                  }}>
                    <CheckCircle2 size={20} color="#4ADE80" style={{ flexShrink: 0 }} />
                    <div style={{ fontSize: 12, color: '#4ADE80', fontWeight: 600 }}>
                      Two-Factor Authentication is now actively enabled!
                    </div>
                  </div>

                  <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 14, lineHeight: 1.5 }}>
                    These <strong style={{ color: '#F5F5F5' }}>8 emergency backup codes</strong> can each be redeemed once
                    to sign in if you ever lose your phone or authenticator app. Download or copy them now.
                  </div>

                  {/* Backup Codes Grid */}
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, 1fr)',
                    gap: 8,
                    background: 'rgba(0, 0, 0, 0.5)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: 8,
                    padding: 14,
                    marginBottom: 16,
                  }}>
                    {backupCodes.map((code, idx) => (
                      <div
                        key={idx}
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 13,
                          fontWeight: 700,
                          color: '#DAFC6F',
                          padding: '6px 8px',
                          background: 'rgba(218, 252, 111, 0.05)',
                          borderRadius: 4,
                          border: '1px solid rgba(218, 252, 111, 0.15)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                        }}
                      >
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{idx + 1}.</span>
                        <span>{code}</span>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
                    <button
                      type="button"
                      onClick={handleCopyBackupCodes}
                      className="btn btn-ghost"
                      style={{
                        flex: 1,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 6,
                        fontSize: 12,
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        color: copiedCodes ? '#4ADE80' : '#F5F5F5',
                      }}
                    >
                      {copiedCodes ? <Check size={14} /> : <Copy size={14} />}
                      {copiedCodes ? 'All Codes Copied!' : 'Copy All Codes'}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownloadBackupCodes}
                      className="btn btn-ghost"
                      style={{
                        flex: 1,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 6,
                        fontSize: 12,
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        color: '#F5F5F5',
                      }}
                    >
                      <Download size={14} /> Download .txt
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={handleFinishSetup}
                    className="btn btn-primary"
                    style={{ width: '100%', padding: '12px 16px', fontWeight: 600, fontSize: 13 }}
                  >
                    I Have Safely Saved My Backup Codes
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── 2FA DISABLE CONFIRMATION MODAL ─────────────────────────────── */}
      <AnimatePresence>
        {showDisableModal && (
          <div className="modal-backdrop" style={{
            position: 'fixed', inset: 0, zIndex: 9999,
            background: 'rgba(0, 0, 0, 0.85)', backdropFilter: 'blur(8px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
          }}>
            <motion.div
              className="card"
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ duration: 0.2 }}
              style={{
                width: '100%',
                maxWidth: 440,
                background: '#14141A',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: 16,
                padding: 24,
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 32, height: 32,
                    borderRadius: 8,
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center'
                  }}>
                    <ShieldAlert size={16} color="#EF4444" />
                  </div>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F5F5' }}>Disable 2FA</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#EF4444' }}>
                      SECURITY PRIVILEGE DOWNGRADE
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setShowDisableModal(false)}
                  style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: 18 }}
                >
                  ✕
                </button>
              </div>

              {disableSuccess ? (
                <div style={{
                  padding: 14,
                  background: 'rgba(34, 197, 94, 0.12)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  borderRadius: 8,
                  textAlign: 'center',
                  color: '#4ADE80',
                  fontSize: 13,
                  fontWeight: 600
                }}>
                  {disableSuccess}
                </div>
              ) : (
                <form onSubmit={handleConfirmDisable}>
                  <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 16, lineHeight: 1.5 }}>
                    Disabling Two-Factor Authentication removes secondary identity verification.
                    Please confirm your current account credentials to proceed.
                  </div>

                  <div className="input-group mb-3">
                    <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>
                      Account Password
                    </label>
                    <input
                      className="input"
                      type="password"
                      placeholder="••••••••"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                      required
                      autoFocus
                    />
                  </div>

                  <div className="input-group mb-4">
                    <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>
                      Google Authenticator Code or Backup Code
                    </label>
                    <input
                      className="input input-mono"
                      type="text"
                      placeholder="000000 or XXXX-XXXX"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value)}
                      required
                      autoComplete="one-time-code"
                      autoCorrect="off"
                      autoCapitalize="off"
                      spellCheck="false"
                      data-lpignore="true"
                    />
                  </div>

                  {disableError && (
                    <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>
                      <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                      <div>{disableError}</div>
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 10 }}>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => setShowDisableModal(false)}
                      style={{ flex: 1 }}
                      disabled={disableLoading}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="btn btn-danger"
                      style={{
                        flex: 1.5,
                        background: '#EF4444',
                        color: '#FFFFFF',
                        border: 'none',
                        fontWeight: 600,
                      }}
                      disabled={disableLoading || !disablePassword}
                    >
                      {disableLoading ? 'Disabling…' : 'Confirm Disablement'}
                    </button>
                  </div>
                </form>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

