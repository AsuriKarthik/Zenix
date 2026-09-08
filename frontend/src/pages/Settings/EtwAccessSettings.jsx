/**
 * ETW Access Settings — Native Zenix System Design
 *
 * Passphrase-gated ETW collector control.
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Lock, AlertTriangle, CheckCircle, ShieldOff, Eye, EyeOff, Shield, Activity,
  Smartphone, QrCode, Copy, Check, X, ShieldCheck
} from 'lucide-react';
import { enableEtw, disableEtw, getTelemetryStatus, sendTelemetryHeartbeat, getEtwAuthenticatorQr } from '../../api/telemetry';
import PulseIndicator from '../../components/ui/PulseIndicator';

export default function EtwAccessSettings() {
  const [status, setStatus]           = useState(null);
  const [passphrase, setPassphrase]   = useState('');
  const [showPass, setShowPass]       = useState(false);
  const [submitting, setSubmitting]   = useState(false);
  const [error, setError]             = useState(null);
  const [success, setSuccess]         = useState(null);
  const [lockoutSecs, setLockoutSecs] = useState(0);

  // 'password' | 'authenticator'
  const [authMode, setAuthMode]       = useState('password');

  // QR Modal for pairing Authenticator app
  const [showQrModal, setShowQrModal] = useState(false);
  const [qrLoading, setQrLoading]     = useState(false);
  const [qrData, setQrData]           = useState(null);
  const [copiedKey, setCopiedKey]     = useState(false);

  const [sessionToken, setSessionToken] = useState(() => localStorage.getItem('zenix_etw_session') || '');

  const fetchStatus = async () => {
    try {
      const s = await getTelemetryStatus();
      setStatus(s);
      if (s.session_token) {
        setSessionToken(s.session_token);
        localStorage.setItem('zenix_etw_session', s.session_token);
      }
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  // Periodic session heartbeat (every 15s) to prevent session auto-expiration while user is active
  useEffect(() => {
    if (!status?.running) return;
    const interval = setInterval(async () => {
      try {
        await sendTelemetryHeartbeat(sessionToken);
      } catch {}
    }, 15000);
    return () => clearInterval(interval);
  }, [status?.running, sessionToken]);

  useEffect(() => {
    if (lockoutSecs <= 0) return;
    const t = setInterval(() => {
      setLockoutSecs(s => {
        if (s <= 1) { clearInterval(t); return 0; }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [lockoutSecs]);

  const handleOpenQrModal = async () => {
    setShowQrModal(true);
    setCopiedKey(false);
    if (!qrData) {
      setQrLoading(true);
      try {
        const data = await getEtwAuthenticatorQr();
        setQrData(data);
      } catch (err) {
        setError('Failed to load Google Authenticator pairing information.');
      } finally {
        setQrLoading(false);
      }
    }
  };

  const handleCopyKey = () => {
    if (qrData?.secret) {
      navigator.clipboard.writeText(qrData.secret);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const handleEnable = async (e) => {
    e.preventDefault();
    if (!passphrase || lockoutSecs > 0) return;
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      const data = await enableEtw(passphrase);
      setSuccess('ETW Collector enabled successfully.');
      setPassphrase('');
      if (data.session_token) {
        setSessionToken(data.session_token);
        localStorage.setItem('zenix_etw_session', data.session_token);
      }
      setStatus(data.status);
    } catch (err) {
      const errData = err.response?.data;
      if (err.response?.status === 429) {
        const match = errData?.error?.match(/(\d+) seconds/);
        if (match) setLockoutSecs(parseInt(match[1], 10));
      }
      if (authMode === 'authenticator') {
        setError(errData?.error || 'Invalid 6-digit Google Authenticator code. Check your app and try again.');
      } else {
        setError(errData?.error || 'Failed to enable ETW collector. Incorrect password.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleDisable = async () => {
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      const data = await disableEtw();
      setSuccess('ETW Collector disabled.');
      setSessionToken('');
      localStorage.removeItem('zenix_etw_session');
      setStatus(data.status || { running: false, collector_status: 'DISABLED' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to disable ETW collector.');
    } finally {
      setSubmitting(false);
    }
  };

  const isRunning = Boolean(status?.running || status?.collector_status === 'ACTIVE');

  return (
    <div>
      {/* Top Grid: Status Card + Control Form */}
      <div className="stat-grid-2 mb-6">
        {/* Status Card */}
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
                <Activity size={16} style={{ color: isRunning ? 'var(--color-verified)' : 'var(--text-muted)' }} />
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>ETW Collector Status</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  PROVIDER: {status?.provider || 'Microsoft-Windows-Kernel-Process'}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <PulseIndicator variant={isRunning ? 'verified' : 'muted'} />
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: 1,
                color: isRunning ? 'var(--color-verified)' : 'var(--text-muted)',
              }}>
                {isRunning ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 'var(--space-3)',
          }}>
            {[
              { label: 'MODE',       value: (status?.mode || '—').toUpperCase() },
              { label: 'ELEVATION',  value: status?.elevation_state || (status?.is_elevated ? 'Elevated (Admin)' : 'Standard User') },
              { label: 'RUNNING',    value: status?.running ? 'YES' : 'NO' },
              { label: 'EVENTS',     value: status?.event_count ?? status?.event_count_total ?? 0 },
            ].map(({ label, value }) => (
              <div key={label} style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Control Form Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">{isRunning ? 'Kernel Telemetry Active' : 'Enable ETW Collection'}</span>
            <span className="card-hud-label">{isRunning ? 'ACTIVE SESSION' : (authMode === 'authenticator' ? 'AUTHENTICATOR CODE REQUIRED' : 'ETW COLLECTOR PASSWORD REQUIRED')}</span>
          </div>

          {!isRunning ? (
            <div>
              <form onSubmit={handleEnable} autoComplete="off">
                <div className="input-group mb-4">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <label className="input-label" htmlFor={authMode === 'authenticator' ? 'etw-authenticator-code' : 'etw-passphrase'} style={{ margin: 0 }}>
                      {authMode === 'authenticator' ? 'Google Authenticator Code' : 'ETW Collector Password'}
                    </label>
                    {authMode === 'password' ? (
                      <button
                        type="button"
                        onClick={() => {
                          setAuthMode('authenticator');
                          setPassphrase('');
                          setError(null);
                        }}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-muted)',
                          fontSize: 11,
                          cursor: 'pointer',
                          padding: 0,
                          transition: 'color 0.2s',
                        }}
                        onMouseEnter={e => e.target.style.color = '#DAFC6F'}
                        onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
                      >
                        Forgot password?
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          setAuthMode('password');
                          setPassphrase('');
                          setError(null);
                        }}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-muted)',
                          fontSize: 11,
                          cursor: 'pointer',
                          padding: 0,
                          transition: 'color 0.2s',
                        }}
                        onMouseEnter={e => e.target.style.color = '#DAFC6F'}
                        onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
                      >
                        Use ETW Password
                      </button>
                    )}
                  </div>

                  {authMode === 'password' ? (
                    <div style={{ position: 'relative' }}>
                      <Lock size={13} style={{
                        position: 'absolute', left: 12, top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'var(--text-muted)',
                        pointerEvents: 'none',
                      }} />
                      <input
                        id="etw-passphrase"
                        name="etw_collector_password"
                        className="input input-mono"
                        type={showPass ? 'text' : 'password'}
                        placeholder="Enter ETW Collector Password"
                        value={passphrase}
                        onChange={e => setPassphrase(e.target.value)}
                        required
                        autoComplete="off"
                        data-lpignore="true"
                        disabled={submitting || lockoutSecs > 0}
                        style={{ paddingLeft: 36, paddingRight: 40 }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPass(v => !v)}
                        style={{
                          position: 'absolute', right: 12, top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none', border: 'none',
                          color: 'var(--text-muted)', cursor: 'pointer',
                        }}
                      >
                        {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    </div>
                  ) : (
                    <div style={{ position: 'relative' }}>
                      <Smartphone size={14} style={{
                        position: 'absolute', left: 12, top: '50%',
                        transform: 'translateY(-50%)',
                        color: '#38BDF8',
                        pointerEvents: 'none',
                      }} />
                      <input
                        id="etw-authenticator-code"
                        name="etw_authenticator_code"
                        className="input input-mono"
                        type="text"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        placeholder="Enter 6-digit Authenticator code"
                        value={passphrase}
                        maxLength={6}
                        onChange={e => setPassphrase(e.target.value.replace(/\D/g, ''))}
                        required
                        autoFocus
                        autoComplete="one-time-code"
                        autoCorrect="off"
                        autoCapitalize="off"
                        spellCheck="false"
                        data-lpignore="true"
                        data-1p-ignore="true"
                        data-form-type="other"
                        disabled={submitting || lockoutSecs > 0}
                        style={{ paddingLeft: 36, paddingRight: 96, letterSpacing: 2 }}
                      />
                      <button
                        type="button"
                        onClick={handleOpenQrModal}
                        title="Show Google Authenticator pairing QR code"
                        style={{
                          position: 'absolute', right: 8, top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'rgba(56, 189, 248, 0.12)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          color: '#38BDF8',
                          borderRadius: 6,
                          padding: '4px 8px',
                          fontSize: 10,
                          fontFamily: 'var(--font-mono)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                        }}
                      >
                        <QrCode size={12} /> Scan QR
                      </button>
                    </div>
                  )}
                </div>

                <AnimatePresence mode="wait">
                  {error && (
                    <motion.div
                      className="alert alert-error mb-4"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    >
                      <AlertTriangle size={14} />
                      <div>
                        {error}
                        {lockoutSecs > 0 && (
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 4 }}>
                            Retry in {lockoutSecs}s
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                  {success && (
                    <motion.div
                      className="alert alert-success mb-4"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    >
                      <CheckCircle size={14} />
                      {success}
                    </motion.div>
                  )}
                </AnimatePresence>

                <button
                  id="etw-enable-btn"
                  type="submit"
                  className="btn btn-primary"
                  disabled={submitting || lockoutSecs > 0 || !passphrase}
                >
                  {submitting
                    ? (authMode === 'authenticator' ? 'Verifying Code…' : 'Enabling…')
                    : lockoutSecs > 0
                    ? `Locked · ${lockoutSecs}s`
                    : (authMode === 'authenticator' ? 'Verify Authenticator & Enable ETW' : 'Enable ETW Collector')
                  }
                </button>
              </form>
            </div>
          ) : (
            <div>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 'var(--space-4)' }}>
                Stop the ETW collector. This will stop runtime evidence collection.
                Audit log entry will be created.
              </p>

              <AnimatePresence mode="wait">
                {error && (
                  <motion.div className="alert alert-error mb-4"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  >
                    <AlertTriangle size={14} />
                    {error}
                  </motion.div>
                )}
                {success && (
                  <motion.div className="alert alert-success mb-4"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  >
                    <CheckCircle size={14} />
                    {success}
                  </motion.div>
                )}
              </AnimatePresence>

              <button
                id="etw-disable-btn"
                className="btn btn-danger"
                onClick={handleDisable}
                disabled={submitting}
              >
                <ShieldOff size={14} />
                {submitting ? 'Disabling…' : 'Disable ETW Collector'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Google Authenticator QR Pairing Modal */}
      <AnimatePresence>
        {showQrModal && (
          <div className="modal-backdrop" style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}>
            <motion.div
              className="card"
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              style={{
                width: '100%',
                maxWidth: 440,
                background: 'var(--bg-surface-1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(56, 189, 248, 0.15)',
                position: 'relative',
                padding: 24,
              }}
            >
              {/* Close button */}
              <button
                type="button"
                onClick={() => setShowQrModal(false)}
                style={{
                  position: 'absolute',
                  top: 16,
                  right: 16,
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                <X size={16} />
              </button>

              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <div style={{
                  width: 40,
                  height: 40,
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <Smartphone size={20} style={{ color: '#38BDF8' }} />
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#FFFFFF' }}>
                    Google Authenticator Setup
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#38BDF8', letterSpacing: 1 }}>
                    ETW RECOVERY ELEVATION KEY
                  </div>
                </div>
              </div>

              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 16 }}>
                Scan this QR code with <strong>Google Authenticator</strong>, <strong>Microsoft Authenticator</strong>, or <strong>Authy</strong> to generate rolling recovery codes.
              </p>

              {qrLoading ? (
                <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text-muted)' }}>
                  Generating secure pairing QR code…
                </div>
              ) : qrData ? (
                <div>
                  {/* QR Code Container */}
                  <div style={{
                    display: 'flex',
                    justifyContent: 'center',
                    marginBottom: 16,
                    padding: 16,
                    background: '#FFFFFF',
                    borderRadius: 12,
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                  }}>
                    <img
                      src={qrData.qr_code_svg}
                      alt="Google Authenticator QR Code"
                      style={{ width: 180, height: 180, display: 'block' }}
                    />
                  </div>

                  {/* Manual Key */}
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                      Manual Secret Key (if unable to scan):
                    </div>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid var(--border-medium)',
                      borderRadius: 8,
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12,
                      letterSpacing: 1,
                      color: '#38BDF8',
                    }}>
                      <span>{qrData.secret}</span>
                      <button
                        type="button"
                        onClick={handleCopyKey}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: copiedKey ? '#4ADE80' : 'var(--text-muted)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: 11,
                        }}
                      >
                        {copiedKey ? <Check size={13} /> : <Copy size={13} />}
                        {copiedKey ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                </div>
              ) : null}

              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setShowQrModal(false)}
                style={{ width: '100%', marginTop: 8 }}
              >
                Done / Enter Code
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
