/**
 * ETW Access Settings — Native Zenix System Design
 *
 * Passphrase-gated ETW collector control.
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, AlertTriangle, CheckCircle, ShieldOff, Eye, EyeOff, Shield, Activity, Key } from 'lucide-react';
import { enableEtw, disableEtw, getTelemetryStatus, sendTelemetryHeartbeat } from '../../api/telemetry';
import { setupEtwPassword } from '../../api/auth';
import PulseIndicator from '../../components/ui/PulseIndicator';

export default function EtwAccessSettings() {
  const [status, setStatus]           = useState(null);
  const [passphrase, setPassphrase]   = useState('');
  const [showPass, setShowPass]       = useState(false);
  const [submitting, setSubmitting]   = useState(false);
  const [error, setError]             = useState(null);
  const [success, setSuccess]         = useState(null);
  const [lockoutSecs, setLockoutSecs] = useState(0);

  // Update ETW Password state
  const [newEtwPass, setNewEtwPass]         = useState('');
  const [confirmEtwPass, setConfirmEtwPass] = useState('');
  const [showNewPass, setShowNewPass]       = useState(false);
  const [updateSubmitting, setUpdateSubmitting] = useState(false);
  const [updateError, setUpdateError]       = useState(null);
  const [updateSuccess, setUpdateSuccess]   = useState(null);

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
      setError(errData?.error || 'Failed to enable ETW collector.');
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

  const handleUpdateEtwPassword = async (e) => {
    e.preventDefault();
    if (newEtwPass !== confirmEtwPass) {
      setUpdateError('New ETW passwords do not match.');
      return;
    }
    if (newEtwPass.length < 6) {
      setUpdateError('ETW Collector Password must be at least 6 characters.');
      return;
    }
    setUpdateSubmitting(true);
    setUpdateError(null);
    setUpdateSuccess(null);
    try {
      await setupEtwPassword(newEtwPass);
      setUpdateSuccess('ETW Collector Password updated successfully! Your new password is saved in zenix.db and will persist for all future ETW activations.');
      setNewEtwPass('');
      setConfirmEtwPass('');
    } catch (err) {
      setUpdateError(err.response?.data?.error || 'Failed to update ETW Collector Password.');
    } finally {
      setUpdateSubmitting(false);
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
            <span className="card-title">{isRunning ? 'Disable ETW Collection' : 'Enable ETW Collection'}</span>
            <span className="card-hud-label">{isRunning ? 'ACTIVE SESSION' : 'ETW COLLECTOR PASSWORD REQUIRED'}</span>
          </div>

          {!isRunning ? (
            <div>
              <form onSubmit={handleEnable}>
                <div className="input-group mb-4">
                  <label className="input-label" htmlFor="etw-passphrase">
                    ETW Collector Password
                  </label>
                  <div style={{ position: 'relative' }}>
                    <Lock size={13} style={{
                      position: 'absolute', left: 12, top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'var(--text-muted)',
                      pointerEvents: 'none',
                    }} />
                    <input
                      id="etw-passphrase"
                      className="input input-mono"
                      type={showPass ? 'text' : 'password'}
                      placeholder="Enter ETW Collector Password (NOT Account/Win Pass)"
                      value={passphrase}
                      onChange={e => setPassphrase(e.target.value)}
                      required
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
                  {submitting ? 'Enabling…' : lockoutSecs > 0 ? `Locked · ${lockoutSecs}s` : 'Enable ETW Collector'}
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

      {/* Update ETW Password Card */}
      <div className="card mb-6">
        <div className="card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Key size={16} style={{ color: '#DAFC6F' }} />
            <span className="card-title">Update ETW Collector Password</span>
          </div>
        </div>

        <form onSubmit={handleUpdateEtwPassword}>
          <div className="stat-grid-2 mb-4">
            <div className="input-group">
              <label className="input-label" htmlFor="new-etw-passphrase">New ETW Collector Password</label>
              <div style={{ position: 'relative' }}>
                <Lock size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                <input
                  id="new-etw-passphrase"
                  className="input input-mono"
                  type={showNewPass ? 'text' : 'password'}
                  placeholder="Enter new ETW password (min 6 chars)"
                  value={newEtwPass}
                  onChange={e => setNewEtwPass(e.target.value)}
                  required
                  disabled={updateSubmitting}
                  style={{ paddingLeft: 36, paddingRight: 40 }}
                />
                <button
                  type="button"
                  onClick={() => setShowNewPass(v => !v)}
                  style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                >
                  {showNewPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <div className="input-group">
              <label className="input-label" htmlFor="confirm-etw-passphrase">Confirm New ETW Password</label>
              <div style={{ position: 'relative' }}>
                <Lock size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                <input
                  id="confirm-etw-passphrase"
                  className="input input-mono"
                  type={showNewPass ? 'text' : 'password'}
                  placeholder="Repeat new ETW password"
                  value={confirmEtwPass}
                  onChange={e => setConfirmEtwPass(e.target.value)}
                  required
                  disabled={updateSubmitting}
                  style={{ paddingLeft: 36 }}
                />
              </div>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {updateError && (
              <motion.div className="alert alert-error mb-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                <AlertTriangle size={14} />
                {updateError}
              </motion.div>
            )}
            {updateSuccess && (
              <motion.div className="alert alert-success mb-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                <CheckCircle size={14} />
                {updateSuccess}
              </motion.div>
            )}
          </AnimatePresence>

          <button
            id="update-etw-password-btn"
            type="submit"
            className="btn btn-primary"
            disabled={updateSubmitting || !newEtwPass || !confirmEtwPass}
          >
            <Key size={14} />
            {updateSubmitting ? 'Updating ETW Password…' : 'Update ETW Password'}
          </button>
        </form>
      </div>
    </div>
  );
}
