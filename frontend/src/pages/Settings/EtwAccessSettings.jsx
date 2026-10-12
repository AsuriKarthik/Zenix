/**
 * ETW Access Settings
 *
 * Purpose: Passphrase-gated ETW collector control.
 *
 * Data sources:
 *   POST /api/telemetry/enable   → requires secondary admin passphrase
 *   POST /api/telemetry/disable  → disable ETW
 *   GET  /api/telemetry/status   → current state
 *
 * Security:
 *   - Rate limited (5 failures → 5 min lockout)
 *   - Audit logged
 *   - Requires elevated Windows privileges for actual ETW
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, AlertTriangle, CheckCircle, ShieldOff, Eye, EyeOff } from 'lucide-react';
import { enableEtw, disableEtw, getTelemetryStatus } from '../../api/telemetry';
import PulseIndicator from '../../components/ui/PulseIndicator';

export default function EtwAccessSettings() {
  const [status, setStatus]       = useState(null);
  const [passphrase, setPassphrase] = useState('');
  const [showPass, setShowPass]   = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]         = useState(null);
  const [success, setSuccess]     = useState(null);
  const [lockoutSecs, setLockoutSecs] = useState(0);

  const fetchStatus = async () => {
    try {
      const s = await getTelemetryStatus();
      setStatus(s);
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
  }, []);

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
      setStatus(data.status);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to disable ETW collector.');
    } finally {
      setSubmitting(false);
    }
  };

  const isRunning = status?.running;

  return (
    <div style={{ maxWidth: 560 }}>
      {/* Current Status */}
      <div className="card mb-6">
        <div className="card-header">
          <span className="card-title">ETW Collector Status</span>
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

        {status && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            {[
              { label: 'MODE',       value: (status.mode || '—').toUpperCase() },
              { label: 'ELEVATION',  value: status.elevation_state || '—' },
              { label: 'RUNNING',    value: status.running ? 'YES' : 'NO' },
              { label: 'EVENTS',     value: status.event_count ?? '—' },
            ].map(({ label, value }) => (
              <div key={label} style={{
                padding: 'var(--space-2) var(--space-3)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-sm)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Enable form */}
      {!isRunning && (
        <div className="card mb-4">
          <div className="card-header">
            <span className="card-title">Enable ETW Collection</span>
            <span className="card-hud-label">SECONDARY PASSPHRASE REQUIRED</span>
          </div>

          <div className="alert alert-warning mb-4">
            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: 12 }}>
              ETW requires elevated Administrator privileges on Windows.
              5 failed attempts will lock this action for 5 minutes.
            </div>
          </div>

          <form onSubmit={handleEnable}>
            <div className="input-group mb-4">
              <label className="input-label" htmlFor="etw-passphrase">
                Admin Passphrase
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
                  placeholder="Secondary admin passphrase"
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
      )}

      {/* Disable button */}
      {isRunning && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Disable ETW Collection</span>
          </div>
          <p style={{ marginBottom: 'var(--space-4)' }}>
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
  );
}
